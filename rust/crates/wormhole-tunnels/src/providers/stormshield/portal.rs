//! Stormshield **Automatic-mode** portal glue (Lab / Fake-first).
//!
//! Mirrors the C# `StormshieldTunnelProvider` / `IStormshieldPortal` /
//! `StormshieldConfigCache` / `StormshieldOtpReuseGuard` / `ITlsTrustPromptService`
//! / `WindowsPhysicalNetworkPathService` flow:
//!
//! 1. Editor settings payload → [`StormshieldPortalSettings`]
//! 2. Physical-path preflight toward the portal host ([`PhysicalNetworkPathProbe`])
//! 3. Profile resolution ([`resolve_automatic_with_consent`]):
//!    - cached profile (`*.ovpncache` DPAPI) + server config hash
//!      (`auth/v1/sslvpn/hash`) → the OTP goes **only** to the data plane
//!    - cache miss → TLS trust consent (when the certificate failed validation) →
//!      `POST auth/config.html?version=1&type=openvpn` with `password + otp`
//!      (single spend) → cache persist → connect **aborts** so the user
//!      reconnects with a fresh code
//! 4. Transport preflight against the profile's `remote` hosts (C#
//!    [`extract_ovpn_remote_hosts`]) + OpenVPN sidecar JSON
//!    ([`stormshield_materials_from_sns`] / [`stormshield_sns_to_sidecar_json`])
//! 5. [`TunnelProvider::establish`] with the shape-gated secret
//!    ([`establish_with_secret`])
//!
//! **No live HTTPS / DNS / OpenVPN.** The portal fetcher and profile cache are
//! injectable seams; [`FakeStormshieldPortalFetcher`] /
//! [`MemoryStormshieldProfileCache`] script them deterministically. DPAPI
//! persistence is real behind the `secrets` feature
//! ([`DpapiStormshieldProfileCache`]) and shares entropy/paths with the
//! `try_read_stormshield_cache` glue. C# transport remotes / DNS resolution /
//! certificate validation live in the managed app and stay unported.
//!
//! Fail-closed matrix (every row is covered by a test):
//!
//! | Condition | Result |
//! |---|---|
//! | Settings payload empty `Server` | `Establish` — "unreadable payload (empty Server). Edit and save the tunnel again." |
//! | Automatic mode without username/password | `Establish` — "'{name}' is in Automatic mode but is missing a username or password." |
//! | Portal destination unclassifiable (`Unknown` / probe error) | `Establish` — "cannot classify its portal destination '{host}'..." |
//! | No active physical adapter | `Establish` — "cannot find an active physical network adapter for its {purpose}. Connect Ethernet, Wi-Fi, or mobile data and try again." |
//! | Cached / downloaded profile with no usable `remote` endpoint | `Establish` — "…contains no usable remote endpoint." (before any sidecar work) |
//! | Transport destination unclassifiable (`Unknown` / probe error) | `Establish` — "cannot classify its transport destination '{host}'..." |
//! | Empty/whitespace downloaded profile | `Establish` **before** any OTP record / cache write |
//! | Cache read / DPAPI / decode failure | defensive cache miss (never propagated) |
//! | Cache schema ≠ 3 / empty profile / empty identity / stale / future stamp | treated as miss |
//! | Server hash unavailable + current cache | optimistic hit; unconfirmed profile dropped on establish failure |
//! | TLS validation failed + trust off | `TlsPreflight` **before** any OTP spend |
//! | Trust prompt rejected / cancelled | `TunnelError::Cancelled` (fail-closed) |
//! | Pinned CA (no `TrustServerCertificate`) | fails closed, **no** trust prompt |
//! | OTP prompt cancelled / empty | `TunnelError::Cancelled` |
//! | OTP code reused inside the 90 s window | `Establish` — "That one-time code was just used. Wait until your authenticator shows a NEW code, then reconnect." |
//! | Fresh profile downloaded (OTP spent on the portal) | connect aborts — "Downloaded an updated VPN profile for '{name}'..." (never echoes the code) |
//! | Config / provider kind mismatch | `WrongKind` / `ConfigNotFound` (via [`load_stormshield_record`]) |
//!
//! **Secrets discipline:** never log settings passwords, OTP codes, cached profile
//! text, or full certificate thumbprints; `Debug` redacts every secret-bearing
//! field (see [`redact_nonempty`]).

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
use crate::providers::auth_glue::try_read_stormshield_cache;
use crate::providers::auth_glue::{
    compose_sns_auth_password, redact_nonempty, request_stormshield_otp, request_tls_trust,
    stormshield_materials_from_sns, stormshield_sns_to_sidecar_json, OtpCode, OtpPrompt,
    StormshieldOvpnCacheRecord, StormshieldPassword, StormshieldUsername, TlsTrustPrompt,
    ACCEPT_BUTTON_LABEL, STORM_SHIELD_CACHE_SCHEMA,
};
use crate::providers::stormshield::establish::{
    establish_with_secret, load_stormshield_record, require_stormshield_provider,
};
use crate::providers::wireguard::TunnelConfigLookup;
use crate::{
    PhysicalNetworkPath, PhysicalNetworkPathProbe, PhysicalNetworkRoute, TunnelError,
    TunnelInstance, TunnelProvider,
};

/// OTP reuse window — C# `StormshieldOtpReuseGuard.DefaultReuseWindow`.
pub const STORMSHIELD_OTP_REUSE_WINDOW: Duration = Duration::from_secs(90);

/// Cached profile max age — C# `StormshieldConfigCache.DefaultMaxAge` (7 days).
pub const STORMSHIELD_CACHE_MAX_AGE: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// Portal form app token — C# `StormshieldSettings.DefaultAppToken`.
pub const STORMSHIELD_DEFAULT_APP_TOKEN: &str = "sslclient";

/// Portal config-download path — C# `IStormshieldPortal.DownloadProfileV5Async`.
pub const STORMSHIELD_CONFIG_DOWNLOAD_PATH: &str = "auth/config.html?version=1&type=openvpn";

/// Portal config-hash path — C# `IStormshieldPortal.GetConfigHashAsync`.
pub const STORMSHIELD_CONFIG_HASH_PATH: &str = "auth/v1/sslvpn/hash";

/// Stormshield Automatic-mode portal settings (C# `StormshieldSettings` shape).
#[derive(Clone, PartialEq, Eq)]
pub struct StormshieldPortalSettings {
    /// Portal host (C# `Server`); never empty for Automatic mode.
    pub server: String,
    /// Portal HTTPS port (C# `Port`, default 443).
    pub port: u16,
    pub username: String,
    pub password: String,
    /// When true, a single-use OTP is concatenated onto the password for the
    /// portal download **and** the OpenVPN data plane (C# `UseOtp`).
    pub use_otp: bool,
    /// Persisted "trust this server certificate" override (C# `TrustServerCertificate`).
    pub trust_server_certificate: bool,
    /// Pinned CA PEM — trust prompts are never offered when set.
    pub ca_pem: Option<String>,
    /// Maximum cached-profile age before it counts as a miss (C# `MaxAge`).
    pub max_cache_age: Duration,
    /// Portal form app token (C# `AppToken`, default `"sslclient"`).
    pub app_token: String,
}

impl StormshieldPortalSettings {
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
            max_cache_age: STORMSHIELD_CACHE_MAX_AGE,
            app_token: STORMSHIELD_DEFAULT_APP_TOKEN.to_string(),
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

    pub fn with_app_token(mut self, token: impl Into<String>) -> Self {
        self.app_token = token.into();
        self
    }

    /// C# `AppToken ?? DefaultAppToken` — blank falls back to the default.
    pub fn effective_app_token(&self) -> &str {
        if self.app_token.trim().is_empty() {
            STORMSHIELD_DEFAULT_APP_TOKEN
        } else {
            &self.app_token
        }
    }

    /// Stable site identity for the profile cache (C# `SiteIdentityHash`).
    ///
    /// **Deliberately excludes the password** — rotating credentials must not
    /// invalidate the cached profile. TLS-trust settings are included because
    /// they change the security posture of the cached profile.
    pub fn site_identity_hash(&self) -> String {
        let joined = format!(
            "{}\n{}\n{}\n{}\n{}\n{}",
            self.server.trim(),
            self.port,
            self.username.trim(),
            self.effective_app_token(),
            if self.trust_server_certificate { "1" } else { "0" },
            self.ca_pem.as_deref().unwrap_or(""),
        );
        sha256_hex_upper(joined.as_bytes())
    }
}

impl Default for StormshieldPortalSettings {
    fn default() -> Self {
        Self {
            server: String::new(),
            port: 443,
            username: String::new(),
            password: String::new(),
            use_otp: false,
            trust_server_certificate: false,
            ca_pem: None,
            max_cache_age: STORMSHIELD_CACHE_MAX_AGE,
            app_token: STORMSHIELD_DEFAULT_APP_TOKEN.to_string(),
        }
    }
}

impl fmt::Debug for StormshieldPortalSettings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StormshieldPortalSettings")
            .field("server", &self.server)
            .field("port", &self.port)
            .field("username", &self.username)
            .field("password", &redact_nonempty(&self.password))
            .field("use_otp", &self.use_otp)
            .field("trust_server_certificate", &self.trust_server_certificate)
            .field("ca_pem_len", &self.ca_pem.as_ref().map(|s| s.len()))
            .field("max_cache_age_secs", &self.max_cache_age.as_secs())
            .field("app_token", &redact_nonempty(&self.app_token))
            .finish()
    }
}

/// Non-secret portal request metadata (host + port only).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StormshieldPortalRequest {
    pub server: String,
    pub port: u16,
}

impl StormshieldPortalRequest {
    pub fn new(server: impl Into<String>, port: u16) -> Self {
        Self {
            server: server.into(),
            port,
        }
    }
}

/// Last TLS validation failure observed by a [`StormshieldPortalFetcher`].
///
/// `Debug` prints a short thumbprint prefix only (never the full value).
#[derive(Clone, PartialEq, Eq)]
pub struct StormshieldTlsFailure {
    pub subject: String,
    pub issuer: String,
    pub thumbprint: String,
}

impl StormshieldTlsFailure {
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

impl fmt::Debug for StormshieldTlsFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StormshieldTlsFailure")
            .field("subject", &self.subject)
            .field("issuer", &self.issuer)
            .field("thumbprint_prefix", &thumbprint_prefix(&self.thumbprint))
            .finish()
    }
}

/// One recorded portal HTTPS attempt (credentials never logged).
#[derive(Clone, PartialEq, Eq)]
pub struct StormshieldPortalFetchCall {
    pub request: StormshieldPortalRequest,
    pub username: String,
    pub password: String,
}

impl StormshieldPortalFetchCall {
    pub fn new(
        request: StormshieldPortalRequest,
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

impl fmt::Debug for StormshieldPortalFetchCall {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StormshieldPortalFetchCall")
            .field("request", &self.request)
            .field("username", &self.username)
            .field("password", &redact_nonempty(&self.password))
            .finish()
    }
}

/// Portal HTTP surface (C# `IStormshieldPortal`), injectable for tests.
///
/// Implementations must never log credentials or OTP codes.
#[async_trait]
pub trait StormshieldPortalFetcher: Send + Sync {
    /// `GET auth/v1/sslvpn/hash` — `Ok(None)` when the appliance does not
    /// expose the endpoint (C# returns `null` for unsupported/unreachable).
    async fn get_config_hash(
        &self,
        request: &StormshieldPortalRequest,
    ) -> Result<Option<String>, TunnelError>;

    /// `POST auth/config.html?version=1&type=openvpn` with form `user`/`pass`
    /// (already `password + otp` when an OTP is spent).
    async fn download_profile(
        &self,
        request: &StormshieldPortalRequest,
        username: &str,
        password: &str,
    ) -> Result<String, TunnelError>;

    /// Last TLS certificate-validation failure, if any.
    fn last_tls_failure(&self) -> Option<StormshieldTlsFailure>;
}

pub type SharedStormshieldPortalFetcher = Arc<dyn StormshieldPortalFetcher>;

enum MemoryPortalHashScript {
    Some(String),
    Unavailable,
    Error(String),
}

enum MemoryPortalProfileScript {
    Ok(String),
    Error(String),
}

/// Scripted in-memory portal — the only [`StormshieldPortalFetcher`] today.
///
/// Hash/profile queues are consumed FIFO; an exhausted script fails closed.
pub struct MemoryStormshieldPortalFetcher {
    hash_scripts: Mutex<VecDeque<MemoryPortalHashScript>>,
    profile_scripts: Mutex<VecDeque<MemoryPortalProfileScript>>,
    calls: Mutex<Vec<StormshieldPortalFetchCall>>,
    hash_calls: AtomicUsize,
    download_calls: AtomicUsize,
    tls_failure: Mutex<Option<StormshieldTlsFailure>>,
}

impl MemoryStormshieldPortalFetcher {
    pub fn new() -> Self {
        Self {
            hash_scripts: Mutex::new(VecDeque::new()),
            profile_scripts: Mutex::new(VecDeque::new()),
            calls: Mutex::new(Vec::new()),
            hash_calls: AtomicUsize::new(0),
            download_calls: AtomicUsize::new(0),
            tls_failure: Mutex::new(None),
        }
    }

    pub fn push_hash(&self, hash: impl Into<String>) {
        self.hash_scripts
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push_back(MemoryPortalHashScript::Some(hash.into()));
    }

    /// Script `Ok(None)` — appliance does not expose the hash endpoint.
    pub fn push_unavailable_hash(&self) {
        self.hash_scripts
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push_back(MemoryPortalHashScript::Unavailable);
    }

    pub fn push_hash_error(&self, message: impl Into<String>) {
        self.hash_scripts
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push_back(MemoryPortalHashScript::Error(message.into()));
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

    pub fn with_hash(self, hash: impl Into<String>) -> Self {
        self.push_hash(hash);
        self
    }

    pub fn with_unavailable_hash(self) -> Self {
        self.push_unavailable_hash();
        self
    }

    pub fn with_hash_error(self, message: impl Into<String>) -> Self {
        self.push_hash_error(message);
        self
    }

    pub fn with_profile(self, profile: impl Into<String>) -> Self {
        self.push_profile(profile);
        self
    }

    pub fn with_profile_error(self, message: impl Into<String>) -> Self {
        self.push_profile_error(message);
        self
    }

    pub fn set_tls_failure(&self, failure: StormshieldTlsFailure) {
        *self
            .tls_failure
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = Some(failure);
    }

    pub fn with_tls_failure(self, failure: StormshieldTlsFailure) -> Self {
        self.set_tls_failure(failure);
        self
    }

    pub fn clear_tls_failure(&self) {
        *self.tls_failure.lock().unwrap_or_else(|p| p.into_inner()) = None;
    }

    pub fn hash_calls(&self) -> usize {
        self.hash_calls.load(Ordering::SeqCst)
    }

    pub fn download_calls(&self) -> usize {
        self.download_calls.load(Ordering::SeqCst)
    }

    /// Download attempts with credentials (test assertions only).
    pub fn download_requests(&self) -> Vec<StormshieldPortalFetchCall> {
        self.calls.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }
}

impl Default for MemoryStormshieldPortalFetcher {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for MemoryStormshieldPortalFetcher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MemoryStormshieldPortalFetcher")
            .field(
                "queued_hashes",
                &self.hash_scripts.lock().unwrap_or_else(|p| p.into_inner()).len(),
            )
            .field(
                "queued_profiles",
                &self.profile_scripts.lock().unwrap_or_else(|p| p.into_inner()).len(),
            )
            .field("hash_calls", &self.hash_calls.load(Ordering::SeqCst))
            .field("download_calls", &self.download_calls.load(Ordering::SeqCst))
            .field(
                "has_tls_failure",
                &self.tls_failure.lock().unwrap_or_else(|p| p.into_inner()).is_some(),
            )
            .finish()
    }
}

#[async_trait]
impl StormshieldPortalFetcher for MemoryStormshieldPortalFetcher {
    async fn get_config_hash(
        &self,
        _request: &StormshieldPortalRequest,
    ) -> Result<Option<String>, TunnelError> {
        self.hash_calls.fetch_add(1, Ordering::SeqCst);
        let script = self
            .hash_scripts
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .pop_front();
        match script {
            Some(MemoryPortalHashScript::Some(hash)) => Ok(Some(hash)),
            Some(MemoryPortalHashScript::Unavailable) => Ok(None),
            Some(MemoryPortalHashScript::Error(message)) => Err(TunnelError::Establish(message)),
            None => Err(TunnelError::Establish(
                "Stormshield portal hash script exhausted (fake)".into(),
            )),
        }
    }

    async fn download_profile(
        &self,
        request: &StormshieldPortalRequest,
        username: &str,
        password: &str,
    ) -> Result<String, TunnelError> {
        self.download_calls.fetch_add(1, Ordering::SeqCst);
        self.calls
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(StormshieldPortalFetchCall::new(
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
                "Stormshield portal profile script exhausted (fake)".into(),
            )),
        }
    }

    fn last_tls_failure(&self) -> Option<StormshieldTlsFailure> {
        self.tls_failure.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }
}

/// Alias used in tests — same type as [`MemoryStormshieldPortalFetcher`].
pub type FakeStormshieldPortalFetcher = MemoryStormshieldPortalFetcher;

/// Profile cache seam (C# `StormshieldConfigCache`).
///
/// `read` returns `Ok(None)` for a missing file; any DPAPI / decode failure is
/// an `Err` that callers treat as a **defensive miss** (never propagated).
pub trait StormshieldProfileCache: Send + Sync {
    fn read(
        &self,
        tunnel_config_id: &Uuid,
    ) -> Result<Option<StormshieldOvpnCacheRecord>, TunnelError>;
    fn write(
        &self,
        tunnel_config_id: &Uuid,
        record: &StormshieldOvpnCacheRecord,
    ) -> Result<(), TunnelError>;
    fn delete(&self, tunnel_config_id: &Uuid) -> Result<(), TunnelError>;
}

/// In-memory profile cache for tests.
#[derive(Default)]
pub struct MemoryStormshieldProfileCache {
    entries: Mutex<HashMap<Uuid, StormshieldOvpnCacheRecord>>,
    read_failure: Mutex<Option<String>>,
    read_calls: AtomicUsize,
    write_calls: AtomicUsize,
    delete_calls: AtomicUsize,
}

impl MemoryStormshieldProfileCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn seed(&self, tunnel_config_id: Uuid, record: StormshieldOvpnCacheRecord) {
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

    pub fn entry(&self, tunnel_config_id: &Uuid) -> Option<StormshieldOvpnCacheRecord> {
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

impl fmt::Debug for MemoryStormshieldProfileCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MemoryStormshieldProfileCache")
            .field("entry_count", &self.entries.lock().unwrap_or_else(|p| p.into_inner()).len())
            .field("read_calls", &self.read_calls.load(Ordering::SeqCst))
            .field("write_calls", &self.write_calls.load(Ordering::SeqCst))
            .field("delete_calls", &self.delete_calls.load(Ordering::SeqCst))
            .finish()
    }
}

impl StormshieldProfileCache for MemoryStormshieldProfileCache {
    fn read(
        &self,
        tunnel_config_id: &Uuid,
    ) -> Result<Option<StormshieldOvpnCacheRecord>, TunnelError> {
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
        record: &StormshieldOvpnCacheRecord,
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

/// Real DPAPI-backed profile cache (C# `StormshieldConfigCache` parity).
///
/// File layout / entropy match `wormhole-secrets-win`
/// (`stormshield_ovpn_cache_path` + `tunnel_id_entropy`) and the
/// `try_read_stormshield_cache` glue. Writes are atomic (temp + rename).
#[cfg(feature = "secrets")]
#[derive(Debug, Default, Clone, Copy)]
pub struct DpapiStormshieldProfileCache;

#[cfg(feature = "secrets")]
impl DpapiStormshieldProfileCache {
    pub fn new() -> Self {
        Self
    }
}

#[cfg(feature = "secrets")]
impl StormshieldProfileCache for DpapiStormshieldProfileCache {
    fn read(
        &self,
        tunnel_config_id: &Uuid,
    ) -> Result<Option<StormshieldOvpnCacheRecord>, TunnelError> {
        try_read_stormshield_cache(tunnel_config_id)
    }

    fn write(
        &self,
        tunnel_config_id: &Uuid,
        record: &StormshieldOvpnCacheRecord,
    ) -> Result<(), TunnelError> {
        let path = wormhole_secrets_win::stormshield_ovpn_cache_path(tunnel_config_id);
        let entropy = wormhole_secrets_win::tunnel_id_entropy(tunnel_config_id);
        let plaintext = encode_stormshield_cache_record(record)?;
        wormhole_secrets_win::write_protected_file_atomic(&path, &plaintext, Some(&entropy))
            .map_err(map_secrets_error)
    }

    fn delete(&self, tunnel_config_id: &Uuid) -> Result<(), TunnelError> {
        let path = wormhole_secrets_win::stormshield_ovpn_cache_path(tunnel_config_id);
        wormhole_secrets_win::delete_protected_file_if_exists(&path).map_err(map_secrets_error)
    }
}

#[cfg(feature = "secrets")]
fn map_secrets_error(error: wormhole_secrets_win::SecretsError) -> TunnelError {
    use wormhole_secrets_win::SecretsError;
    match error {
        SecretsError::UnsupportedPlatform => TunnelError::Establish(
            "Stormshield profile cache requires Windows".into(),
        ),
        SecretsError::DpapiUnprotect | SecretsError::Io(_) => TunnelError::Establish(
            "Stormshield profile cache DPAPI failed".into(),
        ),
        SecretsError::PathNotConfined { .. } => TunnelError::Establish(
            "Stormshield profile cache path is not confined".into(),
        ),
        SecretsError::PasswordTooLarge { .. } => TunnelError::Establish(
            "Stormshield profile cache payload too large".into(),
        ),
        _ => TunnelError::Establish("Stormshield profile cache operation failed".into()),
    }
}

/// Encode a schema-3 cache record as PascalCase JSON (C# `System.Text.Json` shape).
pub fn encode_stormshield_cache_record(
    record: &StormshieldOvpnCacheRecord,
) -> Result<Vec<u8>, TunnelError> {
    if record.schema_version != STORM_SHIELD_CACHE_SCHEMA
        || record.profile_ovpn.trim().is_empty()
        || record.site_identity_hash.trim().is_empty()
    {
        return Err(TunnelError::Establish(
            "tunnel cache JSON is malformed or unsupported schema".into(),
        ));
    }
    let value = serde_json::json!({
        "SchemaVersion": record.schema_version,
        "SiteIdentityHash": record.site_identity_hash.as_str(),
        "ConfigHash": record.config_hash.as_str(),
        "ProfileOvpn": record.profile_ovpn.as_str(),
        "CachedAtUtc": record.cached_at_utc.as_str(),
    });
    serde_json::to_vec(&value)
        .map_err(|_| TunnelError::Establish("tunnel cache JSON encoding failed".into()))
}

/// Whether the text looks like a self-contained OpenVPN profile (C#
/// `StormshieldPortalClient.LooksLikeOpenVpnProfile`): a `remote` directive plus
/// a `dev tun`/`dev tap` device or an inline `<ca>` block. Two independent
/// markers stop an error page that happens to mention one keyword from passing.
pub fn looks_like_openvpn_profile(text: &str) -> bool {
    if text.trim().is_empty() {
        return false;
    }
    let lower = text.to_lowercase();
    let has_remote = lower.contains("remote ");
    let has_device_or_ca = lower.contains("dev tun")
        || lower.contains("dev tap")
        || lower.contains("<ca>");
    has_remote && has_device_or_ca
}

/// Whether a cached record may be reused for the given site identity / max age.
///
/// Fail-closed: wrong schema, empty profile, empty/mismatched identity, a body
/// that does not look like an OpenVPN profile, unparseable or future timestamps
/// all count as a miss (C# `CacheRecord.IsCurrent` / `TryReadAsync` parity).
pub fn stormshield_cache_record_is_current(
    record: &StormshieldOvpnCacheRecord,
    site_identity_hash: &str,
    max_age: Duration,
) -> bool {
    if record.schema_version != STORM_SHIELD_CACHE_SCHEMA {
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

/// Single-spend OTP guard (C# `StormshieldOtpReuseGuard`).
///
/// Records the **spent** code (confirmed portal download) per tunnel and rejects
/// reuse inside [`STORMSHIELD_OTP_REUSE_WINDOW`]. Hash comparison is constant-time;
/// timestamps come from an injectable clock so tests can advance time.
pub struct StormshieldOtpReuseGuard {
    window: Duration,
    clock: Box<dyn Fn() -> DateTime<Utc> + Send + Sync>,
    spent: Mutex<HashMap<Uuid, (Vec<u8>, DateTime<Utc>)>>,
}

impl StormshieldOtpReuseGuard {
    pub fn new() -> Self {
        Self {
            window: STORMSHIELD_OTP_REUSE_WINDOW,
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

    /// Remember a **confirmed** spend so the same code cannot be reused.
    ///
    /// Whitespace-only codes are ignored (they never leave [`request_otp`]).
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

    /// Reject a code that was already spent inside the reuse window.
    pub fn check(&self, tunnel_id: Uuid, code: &OtpCode) -> Result<(), TunnelError> {
        let trimmed = code.as_str().trim();
        if trimmed.is_empty() {
            return Ok(());
        }
        let candidate = sha256_bytes(trimmed.as_bytes());
        let spent = self.spent.lock().unwrap_or_else(|p| p.into_inner());
        if let Some((previous, spent_at)) = spent.get(&tunnel_id) {
            let now = (self.clock)();
            if hashes_equal(previous, &candidate)
                && now
                    .signed_duration_since(*spent_at)
                    .to_std()
                    .is_ok_and(|age| age < self.window)
            {
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

impl Default for StormshieldOtpReuseGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for StormshieldOtpReuseGuard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StormshieldOtpReuseGuard")
            .field("window_secs", &self.window.as_secs())
            .field(
                "tracked_tunnels",
                &self.spent.lock().unwrap_or_else(|p| p.into_inner()).len(),
            )
            .finish()
    }
}

/// Prompt for a Stormshield OTP, rejecting codes spent inside the reuse window.
pub async fn prompt_guarded_stormshield_otp(
    prompt: &dyn OtpPrompt,
    guard: &StormshieldOtpReuseGuard,
    tunnel_id: Uuid,
    config_name: impl AsRef<str>,
) -> Result<OtpCode, TunnelError> {
    let code = request_stormshield_otp(prompt, config_name).await?;
    guard.check(tunnel_id, &code)?;
    Ok(code)
}

/// Fail-closed settings validation (C# `StormshieldTunnelProvider` parity).
pub fn validate_stormshield_portal_settings(
    settings: &StormshieldPortalSettings,
    config_name: &str,
) -> Result<(), TunnelError> {
    if settings.server.trim().is_empty() {
        return Err(TunnelError::Establish(
            "unreadable payload (empty Server). Edit and save the tunnel again.".into(),
        ));
    }
    if settings.username.trim().is_empty() || settings.password.trim().is_empty() {
        return Err(TunnelError::Establish(format!(
            "'{config_name}' is in Automatic mode but is missing a username or password."
        )));
    }
    Ok(())
}

/// Fail-closed physical-path preflight for one or more destinations (portal
/// host at connect, profile `remote` hosts for the transport).
///
/// Unknown classification or a probe error → refuse to establish (no live probe
/// must never guess). An empty path → no active physical adapter.
pub fn require_physical_path(
    config_name: &str,
    probe: &dyn PhysicalNetworkPathProbe,
    hosts: &[&str],
    purpose: &str,
) -> Result<PhysicalNetworkPath, TunnelError> {
    if hosts.is_empty() {
        return Err(TunnelError::Establish(format!(
            "its {purpose} destination is empty; refusing to establish '{config_name}'"
        )));
    }
    for host in hosts {
        match probe.classify_host(host) {
            Ok(PhysicalNetworkRoute::Direct) | Ok(PhysicalNetworkRoute::Physical) => {}
            Ok(PhysicalNetworkRoute::Unknown) | Err(_) => {
                return Err(TunnelError::Establish(format!(
                    "cannot classify its {purpose} destination '{host}' without a live physical network path probe; refusing to establish '{config_name}'"
                )));
            }
        }
    }
    let path = probe.get_best_path(hosts)?;
    if !path.has_any_interface() {
        return Err(TunnelError::Establish(format!(
            "cannot find an active physical network adapter for its {purpose}. Connect Ethernet, Wi-Fi, or mobile data and try again."
        )));
    }
    Ok(path)
}

/// Opaque OpenVPN inline blocks whose contents must never be scanned for
/// directives (C# `IsOpaqueInlineBlock`).
fn is_opaque_inline_block(name: &str) -> bool {
    [
        "ca", "cert", "key", "tls-auth", "tls-crypt", "tls-crypt-v2", "extra-certs", "pkcs12",
        "secret",
    ]
    .iter()
    .any(|block| block.eq_ignore_ascii_case(name))
}

/// `<<name>>`-shaped open tag with no whitespace in the name (C# `TryReadOpenTag`).
fn try_read_open_tag(trimmed: &str) -> Option<String> {
    if trimmed.len() < 3
        || !trimmed.starts_with('<')
        || !trimmed.ends_with('>')
        || trimmed.as_bytes()[1] == b'/'
    {
        return None;
    }
    let name = &trimmed[1..trimmed.len() - 1];
    if name.is_empty()
        || name
            .chars()
            .any(|ch| ch.is_whitespace() || ch == '<' || ch == '>')
    {
        return None;
    }
    Some(name.to_string())
}

/// Exact `</name>` close tag (C# `IsCloseTag`).
fn is_close_tag(trimmed: &str, name: &str) -> bool {
    trimmed.len() == name.len() + 3
        && trimmed.starts_with("</")
        && trimmed.ends_with('>')
        && trimmed[2..trimmed.len() - 1].eq_ignore_ascii_case(name)
}

/// Split an OpenVPN directive line on whitespace, honoring quotes and
/// backslash escapes (C# `TokenizeOpenVpnDirective`).
fn tokenize_ovpn_line(line: &str) -> Vec<String> {
    let mut tokens: Vec<String> = Vec::new();
    let mut token = String::new();
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for ch in line.chars() {
        if escaped {
            token.push(ch);
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
        } else if let Some(active) = quote {
            if ch == active {
                quote = None;
            } else {
                token.push(ch);
            }
        } else if ch == '"' || ch == '\'' {
            quote = Some(ch);
        } else if ch.is_whitespace() {
            if !token.is_empty() {
                tokens.push(std::mem::take(&mut token));
            }
        } else {
            token.push(ch);
        }
    }
    if escaped {
        token.push('\\');
    }
    if !token.is_empty() {
        tokens.push(token);
    }
    tokens
}

/// Distinct `remote` endpoint hosts from an OpenVPN profile (C# `ExtractOpenVpnRemotes`
/// parity, host subset). Comments and opaque inline blocks are skipped; hosts inside
/// `<connection>` blocks count; the first-seen casing wins for duplicate hosts.
///
/// Returns an empty list when the profile has no usable endpoint (callers fail closed).
pub fn extract_ovpn_remote_hosts(profile_ovpn: &str) -> Vec<String> {
    let mut hosts: Vec<String> = Vec::new();
    let mut opaque: Option<String> = None;
    for raw in profile_ovpn.replace("\r\n", "\n").replace('\r', "\n").split('\n') {
        let trimmed = raw.trim();
        if let Some(block) = &opaque {
            if is_close_tag(trimmed, block) {
                opaque = None;
            }
            continue;
        }
        if is_close_tag(trimmed, "connection") || trimmed.is_empty() {
            continue;
        }
        if let Some(name) = try_read_open_tag(trimmed) {
            if is_opaque_inline_block(&name) {
                opaque = Some(name);
            }
            continue;
        }
        if trimmed.starts_with('#') || trimmed.starts_with(';') {
            continue;
        }
        let tokens = tokenize_ovpn_line(trimmed);
        if tokens.len() < 2 || !tokens[0].eq_ignore_ascii_case("remote") {
            continue;
        }
        let host = tokens[1].trim();
        if host.is_empty() {
            continue;
        }
        if hosts.iter().any(|existing| existing.eq_ignore_ascii_case(host)) {
            continue;
        }
        hosts.push(host.to_string());
    }
    hosts
}

/// Reject empty/whitespace portal profiles **before** any OTP record or cache write.
pub fn require_nonempty_profile(profile_ovpn: &str, config_name: &str) -> Result<(), TunnelError> {
    if profile_ovpn.trim().is_empty() {
        return Err(TunnelError::Establish(format!(
            "Stormshield portal returned an empty OpenVPN profile for '{config_name}'"
        )));
    }
    Ok(())
}

/// Resolved Automatic-mode materials ready for the data plane.
#[derive(Clone, PartialEq, Eq)]
pub struct AutomaticOutcome {
    pub profile_ovpn: String,
    /// Data-plane password — already `password + otp` when an OTP was involved.
    pub data_plane_password: String,
    /// Cached profile reused without a fresh server hash (establish failure drops it).
    pub optimistic_cache_hit: bool,
}

impl fmt::Debug for AutomaticOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AutomaticOutcome")
            .field("profile_len", &self.profile_ovpn.len())
            .field(
                "data_plane_password",
                &redact_nonempty(&self.data_plane_password),
            )
            .field("optimistic_cache_hit", &self.optimistic_cache_hit)
            .finish()
    }
}

/// Resolution control flow (not user-facing errors).
#[derive(Debug)]
pub enum ResolveError {
    /// TLS validation failed and consent has not been granted.
    TlsPreflight,
    /// Fresh profile downloaded — the connect must abort (the OTP was spent).
    ConfigRefreshed,
    Other(TunnelError),
}

impl From<TunnelError> for ResolveError {
    fn from(error: TunnelError) -> Self {
        Self::Other(error)
    }
}

/// Convert a resolution control-flow outcome into the user-facing error.
pub fn map_resolve_error(
    config_name: &str,
    settings: &StormshieldPortalSettings,
    error: ResolveError,
) -> TunnelError {
    match error {
        ResolveError::TlsPreflight => TunnelError::Establish(format!(
            "The TLS certificate presented by '{}:{}' could not be verified. To trust this server anyway, enable \"Trust server certificate\" for '{config_name}' or approve the one-time prompt on the next attempt.",
            settings.server, settings.port
        )),
        ResolveError::ConfigRefreshed => TunnelError::Establish(format!(
            "Downloaded an updated VPN profile for '{config_name}'. This used your current one-time code, so enter a NEW code from your authenticator and reconnect to bring up the tunnel (re-using the same code won't work)."
        )),
        ResolveError::Other(error) => error,
    }
}

/// Trust-prompt body for an unverified portal certificate (C# message parity).
pub fn tls_trust_prompt_message(
    settings: &StormshieldPortalSettings,
    failure: &StormshieldTlsFailure,
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
async fn resolve_automatic_core(
    config_id: Uuid,
    config_name: &str,
    settings: &StormshieldPortalSettings,
    fetcher: &dyn StormshieldPortalFetcher,
    cache: &dyn StormshieldProfileCache,
    otp_prompt: &dyn OtpPrompt,
    guard: &StormshieldOtpReuseGuard,
    trust_enabled: bool,
) -> Result<AutomaticOutcome, ResolveError> {
    let request = StormshieldPortalRequest::new(settings.server.trim(), settings.port);

    if !settings.use_otp {
        // No OTP: download with the saved password — never prompt, never touch cache/hash.
        let profile = fetcher
            .download_profile(&request, &settings.username, &settings.password)
            .await?;
        require_nonempty_profile(&profile, config_name)?;
        return Ok(AutomaticOutcome {
            profile_ovpn: profile,
            data_plane_password: settings.password.clone(),
            optimistic_cache_hit: false,
        });
    }

    let site_identity_hash = settings.site_identity_hash();

    // Cached profile fast path (defensive miss on any read failure).
    let cached = match cache.read(&config_id) {
        Ok(cached) => cached,
        Err(error) => {
            tracing::debug!(
                tunnel_config_id = %config_id,
                error = %error,
                "Stormshield profile cache read failed; treating as a miss"
            );
            None
        }
    };
    let usable_cache = cached.as_ref().filter(|record| {
        stormshield_cache_record_is_current(record, &site_identity_hash, settings.max_cache_age)
    });

    // Server-side config hash (defensive None on failure — C# returns null).
    let server_hash = match fetcher.get_config_hash(&request).await {
        Ok(hash) => hash,
        Err(error) => {
            tracing::debug!(
                tunnel_config_id = %config_id,
                error = %error,
                "Stormshield config hash check failed; treating as unavailable"
            );
            None
        }
    };

    if let Some(record) = usable_cache {
        let hash_matches = server_hash
            .as_deref()
            .is_some_and(|server| server.eq_ignore_ascii_case(record.config_hash.trim()));
        if hash_matches || server_hash.is_none() {
            let otp = prompt_guarded_stormshield_otp(otp_prompt, guard, config_id, config_name)
                .await?;
            let data_plane_password = compose_sns_auth_password(&settings.password, Some(&otp));
            return Ok(AutomaticOutcome {
                profile_ovpn: record.profile_ovpn.clone(),
                data_plane_password,
                optimistic_cache_hit: server_hash.is_none(),
            });
        }
    }

    // Cache miss: surface a TLS failure *before* any OTP spend.
    if !trust_enabled && fetcher.last_tls_failure().is_some() {
        return Err(ResolveError::TlsPreflight);
    }

    // Download with `password + otp` — the single confirmed spend.
    let otp = prompt_guarded_stormshield_otp(otp_prompt, guard, config_id, config_name).await?;
    let composed = compose_sns_auth_password(&settings.password, Some(&otp));
    let profile = fetcher
        .download_profile(&request, &settings.username, &composed)
        .await?;
    require_nonempty_profile(&profile, config_name)?;

    // Only a confirmed download records the spent code.
    guard.record(config_id, &otp);

    let record = StormshieldOvpnCacheRecord {
        schema_version: STORM_SHIELD_CACHE_SCHEMA,
        site_identity_hash,
        config_hash: server_hash.unwrap_or_default(),
        profile_ovpn: profile.clone(),
        cached_at_utc: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
    };
    if let Err(error) = cache.write(&config_id, &record) {
        tracing::warn!(
            tunnel_config_id = %config_id,
            error = %error,
            "Stormshield profile cache write failed (best-effort)"
        );
    }

    Err(ResolveError::ConfigRefreshed)
}

/// Automatic-mode resolution with one TLS trust-consent retry (C# parity).
async fn resolve_automatic_with_consent(
    config_id: Uuid,
    config_name: &str,
    settings: &StormshieldPortalSettings,
    fetcher: &dyn StormshieldPortalFetcher,
    cache: &dyn StormshieldProfileCache,
    otp_prompt: &dyn OtpPrompt,
    guard: &StormshieldOtpReuseGuard,
    trust_prompt: &dyn TlsTrustPrompt,
) -> Result<AutomaticOutcome, ResolveError> {
    let mut trust_enabled = settings.trust_server_certificate;
    loop {
        match resolve_automatic_core(
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
            Err(ResolveError::TlsPreflight) => {
                // Fail-closed guard: a pinned CA must never trigger a prompt.
                // Unreachable from resolve_automatic_core's gate today; kept so
                // future edits cannot regress the no-prompt contract.
                if settings.ca_pem.is_some() {
                    return Err(ResolveError::TlsPreflight);
                }
                let Some(failure) = fetcher.last_tls_failure() else {
                    return Err(ResolveError::TlsPreflight);
                };
                let title = format!("Unverified VPN server certificate — {config_name}");
                let message = tls_trust_prompt_message(settings, &failure);
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
                    Ok(false) => return Err(ResolveError::Other(TunnelError::Cancelled)),
                    Err(error) => return Err(ResolveError::Other(error)),
                }
            }
            outcome => return outcome,
        }
    }
}

/// Establish a Stormshield Automatic-mode tunnel end to end (C# `ConnectAutomaticAsync`).
///
/// Order: provider/config kind gate → settings validation → portal physical-path
/// preflight → profile resolution (cache / portal + OTP + trust consent) →
/// transport physical-path preflight → OpenVPN sidecar JSON → establish.
pub async fn establish_stormshield_portal(
    config_id: Uuid,
    configs: &dyn TunnelConfigLookup,
    settings: StormshieldPortalSettings,
    fetcher: &dyn StormshieldPortalFetcher,
    cache: &dyn StormshieldProfileCache,
    probe: &dyn PhysicalNetworkPathProbe,
    otp_prompt: &dyn OtpPrompt,
    otp_guard: &StormshieldOtpReuseGuard,
    trust_prompt: &dyn TlsTrustPrompt,
    provider: &dyn TunnelProvider,
) -> Result<Arc<dyn TunnelInstance>, TunnelError> {
    require_stormshield_provider(provider)?;
    let record = load_stormshield_record(config_id, configs)?;
    let config_name = record.name.clone();

    validate_stormshield_portal_settings(&settings, &config_name)?;

    let _portal_path = require_physical_path(&config_name, probe, &[settings.server.trim()], "portal")?;

    let outcome = resolve_automatic_with_consent(
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
    .map_err(|error| map_resolve_error(&config_name, &settings, error))?;

    // Transport preflight targets the profile's `remote` hosts (C#: the portal
    // server and the OpenVPN endpoint are usually the same appliance, but not
    // always — classification must describe the actual data-plane destination).
    let remote_hosts = extract_ovpn_remote_hosts(&outcome.profile_ovpn);
    if remote_hosts.is_empty() {
        return Err(TunnelError::Establish(format!(
            "Stormshield '{config_name}' OpenVPN profile contains no usable remote endpoint."
        )));
    }
    let remote_host_refs: Vec<&str> = remote_hosts.iter().map(String::as_str).collect();
    let transport = require_physical_path(&config_name, probe, &remote_host_refs, "transport")?;
    let transport_adapter_ids = transport.adapter_ids();
    let optimistic_cache_hit = outcome.optimistic_cache_hit;

    let materials = stormshield_materials_from_sns(
        outcome.profile_ovpn,
        &StormshieldUsername::new(settings.username.clone()),
        &StormshieldPassword::new(outcome.data_plane_password.clone()),
        Some(transport_adapter_ids),
        None,
    );
    let secret = stormshield_sns_to_sidecar_json(&materials)?;

    match establish_with_secret(&record, &secret, provider).await {
        Ok(instance) => Ok(instance),
        Err(error) => {
            if optimistic_cache_hit {
                // Unconfirmed cached profile — drop it so the next attempt downloads.
                if let Err(delete_error) = cache.delete(&config_id) {
                    tracing::warn!(
                        tunnel_config_id = %config_id,
                        error = %delete_error,
                        "failed to drop optimistic Stormshield profile cache entry"
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

    use crate::providers::auth_glue::{decode_stormshield_cache_json, FakeOtpPrompt, FakeTlsTrustPrompt};
    use crate::providers::wireguard::{FakeTunnelConfigLookup, TunnelConfigRecord};
    use crate::{
        FakePhysicalNetworkPath, PhysicalAdapterRecord, PhysicalNetworkRoute, StubTunnelInstance,
        TunnelConfigSnapshot, TunnelKind, TunnelState,
    };

    const TEST_SERVER: &str = "fw.example";
    const TEST_USERNAME: &str = "sns-user";
    const TEST_PASSWORD: &str = "s3cret";
    const TEST_OTP: &str = "654321";
    const TEST_PROFILE: &str = "client\nremote 127.0.0.1 443 tcp\n";
    const TEST_THUMBPRINT: &str =
        "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD";
    const TEST_CONFIG_ID: &str = "cccccccc-dddd-eeee-ffff-000000000001";
    const TEST_CONFIG_ID_2: &str = "cccccccc-dddd-eeee-ffff-000000000002";

    fn config_id() -> Uuid {
        Uuid::parse_str(TEST_CONFIG_ID).unwrap()
    }

    fn config_id_2() -> Uuid {
        Uuid::parse_str(TEST_CONFIG_ID_2).unwrap()
    }

    fn settings() -> StormshieldPortalSettings {
        StormshieldPortalSettings::new(TEST_SERVER, 443, TEST_USERNAME, TEST_PASSWORD, true)
    }

    fn settings_no_otp() -> StormshieldPortalSettings {
        StormshieldPortalSettings::new(TEST_SERVER, 443, TEST_USERNAME, TEST_PASSWORD, false)
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
            TunnelKind::Stormshield,
            "lab-stormshield",
        ))
    }

    fn fresh_stamp() -> String {
        Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)
    }

    fn current_cache_record(site_identity_hash: &str) -> StormshieldOvpnCacheRecord {
        StormshieldOvpnCacheRecord {
            schema_version: STORM_SHIELD_CACHE_SCHEMA,
            site_identity_hash: site_identity_hash.to_string(),
            config_hash: "abc123".to_string(),
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

    /// Controllable Stormshield `TunnelProvider` that records the last secret blob.
    struct RecordingStormshieldProvider {
        kind: TunnelKind,
        establish_count: AtomicUsize,
        fail_next: Mutex<bool>,
        last_secret: Mutex<Option<Vec<u8>>>,
    }

    impl RecordingStormshieldProvider {
        fn new() -> Self {
            Self {
                kind: TunnelKind::Stormshield,
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

    #[async_trait]
    impl TunnelProvider for RecordingStormshieldProvider {
        fn kind(&self) -> TunnelKind {
            self.kind
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
            Ok(StubTunnelInstance::up_with_socks(18_801))
        }
    }

    /// Parse the data-plane password from the recorded sidecar JSON.
    fn sidecar_password(secret: &[u8]) -> String {
        let value: serde_json::Value = serde_json::from_slice(secret).expect("sidecar JSON");
        value["password"].as_str().unwrap_or_default().to_string()
    }

    #[allow(clippy::too_many_arguments)]
    async fn establish_portal(
        fetcher: &dyn StormshieldPortalFetcher,
        cache: &dyn StormshieldProfileCache,
        probe: &dyn PhysicalNetworkPathProbe,
        prompt: &dyn OtpPrompt,
        guard: &StormshieldOtpReuseGuard,
        trust: &dyn TlsTrustPrompt,
        provider: &RecordingStormshieldProvider,
        settings: StormshieldPortalSettings,
    ) -> Result<Arc<dyn TunnelInstance>, TunnelError> {
        establish_stormshield_portal(
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
    async fn no_otp_downloads_fresh_profile_and_establishes() {
        let fetcher = FakeStormshieldPortalFetcher::new();
        fetcher.push_profile(TEST_PROFILE);
        let cache = MemoryStormshieldProfileCache::new();
        let guard = StormshieldOtpReuseGuard::new();
        let prompt = FakeOtpPrompt::from_submitted(["SHOULD_NOT_PROMPT"]);
        let trust = trust_accepting();
        let provider = RecordingStormshieldProvider::new();

        let instance = establish_portal(
            &fetcher,
            &cache,
            &ethernet_probe(),
            &prompt,
            &guard,
            &trust,
            &provider,
            settings_no_otp(),
        )
        .await
        .unwrap();

        assert_eq!(instance.state(), TunnelState::Up);
        assert_eq!(provider.establish_count(), 1);
        assert_eq!(sidecar_password(&provider.last_secret().unwrap()), TEST_PASSWORD);
        assert_eq!(fetcher.download_calls(), 1);
        assert_eq!(fetcher.hash_calls(), 0, "no-OTP path must not touch the hash endpoint");
        assert_eq!(prompt.prompt_count(), 0, "no-OTP path must never prompt");
        assert_eq!(trust.prompt_count(), 0);
        assert_eq!(cache.read_calls(), 0, "no-OTP path must not touch the cache");
        assert_eq!(cache.write_calls(), 0);
    }

    #[tokio::test]
    async fn otp_cache_hit_routes_otp_to_data_plane() {
        let settings = settings();
        let cache = MemoryStormshieldProfileCache::new();
        cache.seed(config_id(), current_cache_record(&settings.site_identity_hash()));
        let fetcher = FakeStormshieldPortalFetcher::new();
        fetcher.push_hash("abc123");
        let guard = StormshieldOtpReuseGuard::new();
        let prompt = FakeOtpPrompt::from_submitted([TEST_OTP]);
        let trust = trust_rejecting();
        let provider = RecordingStormshieldProvider::new();

        let instance = establish_portal(
            &fetcher,
            &cache,
            &ethernet_probe(),
            &prompt,
            &guard,
            &trust,
            &provider,
            settings,
        )
        .await
        .unwrap();

        assert_eq!(instance.state(), TunnelState::Up);
        assert_eq!(provider.establish_count(), 1);
        assert_eq!(
            sidecar_password(&provider.last_secret().unwrap()),
            format!("{TEST_PASSWORD}{TEST_OTP}"),
            "OTP goes to the data plane on a cache hit"
        );
        assert_eq!(fetcher.download_calls(), 0, "cache hit must not download");
        assert_eq!(fetcher.hash_calls(), 1);
        assert_eq!(prompt.prompt_count(), 1);
        assert_eq!(trust.prompt_count(), 0);
        assert_eq!(cache.write_calls(), 0, "cache hit must not rewrite the profile");
        assert!(
            guard.check(config_id(), &OtpCode::new(TEST_OTP)).is_ok(),
            "data-plane codes must never be recorded as spent"
        );
    }

    #[tokio::test]
    async fn otp_optimistic_hit_when_hash_check_unavailable() {
        let settings = settings();
        let cache = MemoryStormshieldProfileCache::new();
        cache.seed(config_id(), current_cache_record(&settings.site_identity_hash()));
        let fetcher = FakeStormshieldPortalFetcher::new();
        fetcher.push_unavailable_hash();
        let guard = StormshieldOtpReuseGuard::new();
        let prompt = FakeOtpPrompt::from_submitted(["111222"]);
        let trust = trust_rejecting();
        let provider = RecordingStormshieldProvider::new();

        let instance = establish_portal(
            &fetcher,
            &cache,
            &ethernet_probe(),
            &prompt,
            &guard,
            &trust,
            &provider,
            settings,
        )
        .await
        .unwrap();

        assert_eq!(instance.state(), TunnelState::Up);
        assert_eq!(sidecar_password(&provider.last_secret().unwrap()), "s3cret111222");
        assert_eq!(fetcher.download_calls(), 0);
        assert_eq!(fetcher.hash_calls(), 1);
        assert_eq!(trust.prompt_count(), 0);
    }

    #[tokio::test]
    async fn otp_cache_miss_downloads_persists_and_aborts() {
        let settings = settings();
        let cache = MemoryStormshieldProfileCache::new();
        let fetcher = FakeStormshieldPortalFetcher::new();
        fetcher.push_unavailable_hash();
        fetcher.push_profile(TEST_PROFILE);
        let guard = StormshieldOtpReuseGuard::new();
        let prompt = FakeOtpPrompt::from_submitted(["999888"]);
        let trust = trust_rejecting();
        let provider = RecordingStormshieldProvider::new();

        let error = establish_portal(
            &fetcher,
            &cache,
            &ethernet_probe(),
            &prompt,
            &guard,
            &trust,
            &provider,
            settings,
        )
        .await
        .err()
        .expect("expected establishment failure");

        let message = error.to_string();
        assert!(message.contains("Downloaded an updated VPN profile"), "unexpected: {message}");
        assert!(message.contains("NEW code"), "unexpected: {message}");
        assert!(!message.contains("999888"), "error must never echo the OTP: {message}");
        assert_eq!(provider.establish_count(), 0, "connect must abort after the download");
        assert_eq!(fetcher.download_calls(), 1);
        assert_eq!(prompt.prompt_count(), 1);
        assert_eq!(cache.write_calls(), 1, "fresh profile must be persisted");
        let stored = cache.entry(&config_id()).expect("profile must be cached");
        assert_eq!(stored.profile_ovpn, TEST_PROFILE);
        assert_eq!(stored.config_hash, "", "unavailable hash stores as empty");

        let reuse = guard.check(config_id(), &OtpCode::new("999888"));
        assert!(reuse.is_err(), "the spent code must be rejected");
        assert!(reuse.unwrap_err().to_string().contains("NEW code"));
    }

    #[tokio::test]
    async fn stale_cache_misses_and_redownloads() {
        let settings = settings();
        let mut record = current_cache_record(&settings.site_identity_hash());
        record.cached_at_utc = (Utc::now() - chrono::Duration::days(8))
            .to_rfc3339_opts(SecondsFormat::Secs, true);
        let cache = MemoryStormshieldProfileCache::new();
        cache.seed(config_id(), record);
        let fetcher = FakeStormshieldPortalFetcher::new();
        fetcher.push_hash("abc123");
        fetcher.push_profile(TEST_PROFILE);
        let prompt = FakeOtpPrompt::from_submitted(["123456"]);

        let error = establish_portal(
            &fetcher,
            &cache,
            &ethernet_probe(),
            &prompt,
            &StormshieldOtpReuseGuard::new(),
            &trust_rejecting(),
            &RecordingStormshieldProvider::new(),
            settings,
        )
        .await
        .err()
        .expect("expected establishment failure");

        assert!(error.to_string().contains("Downloaded an updated VPN profile"));
        assert_eq!(fetcher.download_calls(), 1);
    }

    #[tokio::test]
    async fn identity_mismatch_treats_cache_as_miss() {
        let settings = settings();
        let mut record = current_cache_record(&settings.site_identity_hash());
        record.site_identity_hash = "SOMETHING_ELSE".to_string();
        let cache = MemoryStormshieldProfileCache::new();
        cache.seed(config_id(), record);
        let fetcher = FakeStormshieldPortalFetcher::new();
        fetcher.push_hash("abc123");
        fetcher.push_profile(TEST_PROFILE);
        let prompt = FakeOtpPrompt::from_submitted(["121212"]);

        let error = establish_portal(
            &fetcher,
            &cache,
            &ethernet_probe(),
            &prompt,
            &StormshieldOtpReuseGuard::new(),
            &trust_rejecting(),
            &RecordingStormshieldProvider::new(),
            settings,
        )
        .await
        .err()
        .expect("expected establishment failure");

        assert!(error.to_string().contains("Downloaded an updated VPN profile"));
        assert_eq!(fetcher.download_calls(), 1);
    }

    #[tokio::test]
    async fn corrupt_cache_schema_or_empty_profile_never_reused() {
        let settings = settings();
        let base = current_cache_record(&settings.site_identity_hash());

        let cache = MemoryStormshieldProfileCache::new();
        let mut wrong_schema = base.clone();
        wrong_schema.schema_version = 2;
        cache.seed(config_id(), wrong_schema);
        let fetcher = FakeStormshieldPortalFetcher::new();
        fetcher.push_hash("abc123");
        fetcher.push_profile(TEST_PROFILE);

        let error = establish_portal(
            &fetcher,
            &cache,
            &ethernet_probe(),
            &FakeOtpPrompt::from_submitted(["424242"]),
            &StormshieldOtpReuseGuard::new(),
            &trust_rejecting(),
            &RecordingStormshieldProvider::new(),
            settings.clone(),
        )
        .await
        .err()
        .expect("expected establishment failure");
        assert!(error.to_string().contains("Downloaded an updated VPN profile"));
        assert_eq!(fetcher.download_calls(), 1);

        let cache = MemoryStormshieldProfileCache::new();
        let mut empty_profile = base;
        empty_profile.profile_ovpn = "   ".to_string();
        cache.seed(config_id(), empty_profile);
        let fetcher = FakeStormshieldPortalFetcher::new();
        fetcher.push_hash("abc123");
        fetcher.push_profile(TEST_PROFILE);

        let error = establish_portal(
            &fetcher,
            &cache,
            &ethernet_probe(),
            &FakeOtpPrompt::from_submitted(["515151"]),
            &StormshieldOtpReuseGuard::new(),
            &trust_rejecting(),
            &RecordingStormshieldProvider::new(),
            settings,
        )
        .await
        .err()
        .expect("expected establishment failure");
        assert!(error.to_string().contains("Downloaded an updated VPN profile"));
        assert_eq!(fetcher.download_calls(), 1);
    }

    #[tokio::test]
    async fn cache_read_failure_treated_as_miss() {
        let settings = settings();
        let cache = MemoryStormshieldProfileCache::new();
        cache.set_read_failure("simulated DPAPI failure");
        let fetcher = FakeStormshieldPortalFetcher::new();
        fetcher.push_unavailable_hash();
        fetcher.push_profile(TEST_PROFILE);

        let error = establish_portal(
            &fetcher,
            &cache,
            &ethernet_probe(),
            &FakeOtpPrompt::from_submitted(["313131"]),
            &StormshieldOtpReuseGuard::new(),
            &trust_rejecting(),
            &RecordingStormshieldProvider::new(),
            settings,
        )
        .await
        .err()
        .expect("expected establishment failure");

        assert!(
            error.to_string().contains("Downloaded an updated VPN profile"),
            "read failures must degrade to a download, not propagate"
        );
        assert_eq!(fetcher.download_calls(), 1);
    }

    #[tokio::test]
    async fn tls_preflight_fails_fast_before_otp_prompt() {
        let settings = settings();
        let fetcher = FakeStormshieldPortalFetcher::new();
        fetcher.push_unavailable_hash();
        fetcher.set_tls_failure(StormshieldTlsFailure::new(
            "CN=fw.example",
            "CN=Lab Root CA",
            TEST_THUMBPRINT,
        ));
        let prompt = FakeOtpPrompt::from_submitted([TEST_OTP]);
        let trust = trust_rejecting();

        let error = establish_portal(
            &fetcher,
            &MemoryStormshieldProfileCache::new(),
            &ethernet_probe(),
            &prompt,
            &StormshieldOtpReuseGuard::new(),
            &trust,
            &RecordingStormshieldProvider::new(),
            settings,
        )
        .await
        .err()
        .expect("expected establishment failure");

        assert!(
            matches!(error, TunnelError::Cancelled),
            "unexpected: {error:?}"
        );
        assert_eq!(prompt.prompt_count(), 0, "OTP must not be prompted before TLS consent");
        assert_eq!(fetcher.download_calls(), 0);
        assert_eq!(fetcher.hash_calls(), 1);
        assert_eq!(trust.prompt_count(), 1, "trust consent is the first user interaction");
    }

    #[tokio::test]
    async fn trust_accept_retries_downloads_and_aborts() {
        let settings = settings();
        let fetcher = FakeStormshieldPortalFetcher::new();
        fetcher.push_unavailable_hash();
        fetcher.push_unavailable_hash();
        fetcher.push_profile(TEST_PROFILE);
        fetcher.set_tls_failure(StormshieldTlsFailure::new(
            "CN=fw.example",
            "CN=Lab Root CA",
            TEST_THUMBPRINT,
        ));
        let prompt = FakeOtpPrompt::from_submitted([TEST_OTP]);
        let trust = trust_accepting();

        let error = establish_portal(
            &fetcher,
            &MemoryStormshieldProfileCache::new(),
            &ethernet_probe(),
            &prompt,
            &StormshieldOtpReuseGuard::new(),
            &trust,
            &RecordingStormshieldProvider::new(),
            settings,
        )
        .await
        .err()
        .expect("expected establishment failure");

        let message = error.to_string();
        assert!(
            message.contains("Downloaded an updated VPN profile"),
            "accepting trust still spends the OTP on the download: {message}"
        );
        assert_eq!(fetcher.hash_calls(), 2, "hash re-checked after trust");
        assert_eq!(fetcher.download_calls(), 1);
        assert_eq!(prompt.prompt_count(), 1);
        assert_eq!(trust.prompt_count(), 1);
        assert_eq!(
            fetcher.download_requests()[0].password,
            format!("{TEST_PASSWORD}{TEST_OTP}"),
            "portal download receives password + otp"
        );
        let requests = trust.requests();
        assert_eq!(requests.len(), 1);
        assert!(requests[0].title.contains("lab-stormshield"));
        assert!(requests[0].message.contains("factory certificate"));
        assert!(requests[0].message.contains("one-time code"));
        assert_eq!(requests[0].fingerprint.as_deref(), Some(TEST_THUMBPRINT));
    }

    #[tokio::test]
    async fn trust_reject_fails_closed() {
        let settings = settings();
        let fetcher = FakeStormshieldPortalFetcher::new();
        fetcher.push_unavailable_hash();
        fetcher.set_tls_failure(StormshieldTlsFailure::new(
            "CN=fw.example",
            "CN=Lab Root CA",
            TEST_THUMBPRINT,
        ));
        let prompt = FakeOtpPrompt::from_submitted([TEST_OTP]);
        let trust = trust_rejecting();

        let error = establish_portal(
            &fetcher,
            &MemoryStormshieldProfileCache::new(),
            &ethernet_probe(),
            &prompt,
            &StormshieldOtpReuseGuard::new(),
            &trust,
            &RecordingStormshieldProvider::new(),
            settings,
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
        let fetcher = FakeStormshieldPortalFetcher::new();
        fetcher.push_unavailable_hash();
        fetcher.set_tls_failure(StormshieldTlsFailure::new(
            "CN=fw.example",
            "CN=Lab Root CA",
            TEST_THUMBPRINT,
        ));
        let prompt = FakeOtpPrompt::from_codes([None::<&str>]);
        let trust = trust_accepting();

        let error = establish_portal(
            &fetcher,
            &MemoryStormshieldProfileCache::new(),
            &ethernet_probe(),
            &prompt,
            &StormshieldOtpReuseGuard::new(),
            &trust,
            &RecordingStormshieldProvider::new(),
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
        let cache = MemoryStormshieldProfileCache::new();
        cache.seed(config_id(), current_cache_record(&settings.site_identity_hash()));
        let fetcher = FakeStormshieldPortalFetcher::new();
        fetcher.push_hash("abc123");
        fetcher.set_tls_failure(StormshieldTlsFailure::new(
            "CN=fw.example",
            "CN=Lab Root CA",
            TEST_THUMBPRINT,
        ));
        let trust = trust_rejecting();
        let provider = RecordingStormshieldProvider::new();

        let instance = establish_portal(
            &fetcher,
            &cache,
            &ethernet_probe(),
            &FakeOtpPrompt::from_submitted([TEST_OTP]),
            &StormshieldOtpReuseGuard::new(),
            &trust,
            &provider,
            settings,
        )
        .await
        .unwrap();

        assert_eq!(instance.state(), TunnelState::Up);
        assert_eq!(trust.prompt_count(), 0, "pre-enabled trust must not prompt");
        assert_eq!(fetcher.download_calls(), 0);
        assert_eq!(provider.establish_count(), 1);
    }

    #[tokio::test]
    async fn settings_preflight_fails_closed() {
        let empty_server = StormshieldPortalSettings::new("", 443, TEST_USERNAME, TEST_PASSWORD, true);
        let error = establish_portal(
            &FakeStormshieldPortalFetcher::new(),
            &MemoryStormshieldProfileCache::new(),
            &ethernet_probe(),
            &FakeOtpPrompt::from_submitted([TEST_OTP]),
            &StormshieldOtpReuseGuard::new(),
            &trust_rejecting(),
            &RecordingStormshieldProvider::new(),
            empty_server,
        )
        .await
        .err()
        .expect("expected establishment failure");
        assert!(
            error.to_string().contains("empty Server"),
            "unexpected: {error}"
        );

        let missing_credentials =
            StormshieldPortalSettings::new(TEST_SERVER, 443, "", "", true);
        let error = establish_portal(
            &FakeStormshieldPortalFetcher::new(),
            &MemoryStormshieldProfileCache::new(),
            &ethernet_probe(),
            &FakeOtpPrompt::from_submitted([TEST_OTP]),
            &StormshieldOtpReuseGuard::new(),
            &trust_rejecting(),
            &RecordingStormshieldProvider::new(),
            missing_credentials,
        )
        .await
        .err()
        .expect("expected establishment failure");
        assert!(
            error.to_string().contains("missing a username or password"),
            "unexpected: {error}"
        );

        let whitespace_password =
            StormshieldPortalSettings::new(TEST_SERVER, 443, TEST_USERNAME, "   ", true);
        let error = establish_portal(
            &FakeStormshieldPortalFetcher::new(),
            &MemoryStormshieldProfileCache::new(),
            &ethernet_probe(),
            &FakeOtpPrompt::from_submitted([TEST_OTP]),
            &StormshieldOtpReuseGuard::new(),
            &trust_rejecting(),
            &RecordingStormshieldProvider::new(),
            whitespace_password,
        )
        .await
        .err()
        .expect("expected establishment failure");
        assert!(
            error.to_string().contains("missing a username or password"),
            "whitespace-only password must fail closed, got: {error}"
        );
    }

    #[tokio::test]
    async fn config_missing_or_wrong_kind_fails_closed() {
        let fetcher = FakeStormshieldPortalFetcher::new();
        let cache = MemoryStormshieldProfileCache::new();
        let probe = ethernet_probe();
        let prompt = FakeOtpPrompt::from_submitted([TEST_OTP]);
        let guard = StormshieldOtpReuseGuard::new();
        let trust = trust_rejecting();
        let provider = RecordingStormshieldProvider::new();

        let error = establish_stormshield_portal(
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
            "not-stormshield",
        ));
        let error = establish_stormshield_portal(
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
        // No active adapter.
        let probe =
            FakePhysicalNetworkPath::new(vec![]).with_default_route(PhysicalNetworkRoute::Physical);
        let error = establish_portal(
            &FakeStormshieldPortalFetcher::new(),
            &MemoryStormshieldProfileCache::new(),
            &probe,
            &FakeOtpPrompt::from_submitted([TEST_OTP]),
            &StormshieldOtpReuseGuard::new(),
            &trust_rejecting(),
            &RecordingStormshieldProvider::new(),
            settings(),
        )
        .await
        .err()
        .expect("expected establishment failure");
        assert!(
            error.to_string().contains("physical network adapter"),
            "unexpected: {error}"
        );

        // Unclassifiable host (no live probe) must never guess.
        let probe = FakePhysicalNetworkPath::new(vec![PhysicalAdapterRecord::ethernet(
            "eth0", "Ethernet", 1, 1,
        )]);
        let error = establish_portal(
            &FakeStormshieldPortalFetcher::new(),
            &MemoryStormshieldProfileCache::new(),
            &probe,
            &FakeOtpPrompt::from_submitted([TEST_OTP]),
            &StormshieldOtpReuseGuard::new(),
            &trust_rejecting(),
            &RecordingStormshieldProvider::new(),
            settings(),
        )
        .await
        .err()
        .expect("expected establishment failure");
        assert!(error.to_string().contains("cannot classify"), "unexpected: {error}");
    }

    #[tokio::test]
    async fn otp_prompt_cancel_fails_closed() {
        let fetcher = FakeStormshieldPortalFetcher::new();
        fetcher.push_unavailable_hash();
        fetcher.push_profile(TEST_PROFILE);
        let prompt = FakeOtpPrompt::from_codes([None::<&str>]);

        let error = establish_portal(
            &fetcher,
            &MemoryStormshieldProfileCache::new(),
            &ethernet_probe(),
            &prompt,
            &StormshieldOtpReuseGuard::new(),
            &trust_rejecting(),
            &RecordingStormshieldProvider::new(),
            settings(),
        )
        .await
        .err()
        .expect("expected establishment failure");

        assert!(matches!(error, TunnelError::Cancelled));
        assert_eq!(fetcher.download_calls(), 0);
    }

    #[tokio::test]
    async fn empty_downloaded_profile_fails_before_record_or_cache() {
        let fetcher = FakeStormshieldPortalFetcher::new();
        fetcher.push_unavailable_hash();
        fetcher.push_profile("   ");
        let guard = StormshieldOtpReuseGuard::new();
        let cache = MemoryStormshieldProfileCache::new();

        let error = establish_portal(
            &fetcher,
            &cache,
            &ethernet_probe(),
            &FakeOtpPrompt::from_submitted([TEST_OTP]),
            &guard,
            &trust_rejecting(),
            &RecordingStormshieldProvider::new(),
            settings(),
        )
        .await
        .err()
        .expect("expected establishment failure");

        assert!(
            error.to_string().contains("empty OpenVPN profile"),
            "unexpected: {error}"
        );
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
        let cache = MemoryStormshieldProfileCache::new();
        cache.seed(config_id(), record);
        let fetcher = FakeStormshieldPortalFetcher::new();
        fetcher.push_hash("abc123");
        let provider = RecordingStormshieldProvider::new();

        let error = establish_portal(
            &fetcher,
            &cache,
            &ethernet_probe(),
            &FakeOtpPrompt::from_submitted([TEST_OTP]),
            &StormshieldOtpReuseGuard::new(),
            &trust_rejecting(),
            &provider,
            settings,
        )
        .await
        .err()
        .expect("expected establishment failure");

        let message = error.to_string();
        assert!(
            message.contains("no usable remote endpoint"),
            "unexpected: {message}"
        );
        assert_eq!(provider.establish_count(), 0, "no sidecar work without an endpoint");
        assert_eq!(fetcher.download_calls(), 0, "cache hit must not download");
    }

    #[tokio::test]
    async fn fresh_profile_without_remote_fails_closed_before_sidecar() {
        let fetcher = FakeStormshieldPortalFetcher::new();
        fetcher.push_profile("client\ndev tun\n");
        let provider = RecordingStormshieldProvider::new();

        let error = establish_portal(
            &fetcher,
            &MemoryStormshieldProfileCache::new(),
            &ethernet_probe(),
            &FakeOtpPrompt::from_submitted(["SHOULD_NOT_PROMPT"]),
            &StormshieldOtpReuseGuard::new(),
            &trust_accepting(),
            &provider,
            settings_no_otp(),
        )
        .await
        .err()
        .expect("expected establishment failure");

        let message = error.to_string();
        assert!(
            message.contains("no usable remote endpoint"),
            "unexpected: {message}"
        );
        assert_eq!(provider.establish_count(), 0);
    }

    #[tokio::test]
    async fn transport_unknown_profile_remote_fails_closed() {
        let settings = settings();
        let mut record = current_cache_record(&settings.site_identity_hash());
        record.profile_ovpn =
            "client\nremote unknown-endpoint.example 1194 tcp\ndev tun\n".to_string();
        let cache = MemoryStormshieldProfileCache::new();
        cache.seed(config_id(), record);
        let fetcher = FakeStormshieldPortalFetcher::new();
        fetcher.push_hash("abc123");
        let provider = RecordingStormshieldProvider::new();

        let error = establish_portal(
            &fetcher,
            &cache,
            &ethernet_probe(),
            &FakeOtpPrompt::from_submitted([TEST_OTP]),
            &StormshieldOtpReuseGuard::new(),
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
    async fn cache_body_not_looking_like_ovpn_treated_as_miss() {
        let settings = settings();
        let mut record = current_cache_record(&settings.site_identity_hash());
        record.profile_ovpn = "<html><body>remote login failed</body></html>".to_string();
        let cache = MemoryStormshieldProfileCache::new();
        cache.seed(config_id(), record);
        let fetcher = FakeStormshieldPortalFetcher::new();
        fetcher.push_hash("abc123");
        fetcher.push_profile(TEST_PROFILE);

        let error = establish_portal(
            &fetcher,
            &cache,
            &ethernet_probe(),
            &FakeOtpPrompt::from_submitted(["222333"]),
            &StormshieldOtpReuseGuard::new(),
            &trust_rejecting(),
            &RecordingStormshieldProvider::new(),
            settings,
        )
        .await
        .err()
        .expect("expected establishment failure");

        let message = error.to_string();
        assert!(
            message.contains("Downloaded an updated VPN profile"),
            "garbage cache body must re-download: {message}"
        );
        assert_eq!(fetcher.download_calls(), 1);
    }

    #[tokio::test]
    async fn optimistic_hit_drops_unconfirmed_profile_on_establish_failure() {
        let settings = settings();
        let cache = MemoryStormshieldProfileCache::new();
        cache.seed(config_id(), current_cache_record(&settings.site_identity_hash()));
        let fetcher = FakeStormshieldPortalFetcher::new();
        fetcher.push_unavailable_hash();
        let provider = RecordingStormshieldProvider::new();
        provider.fail_next();

        let error = establish_portal(
            &fetcher,
            &cache,
            &ethernet_probe(),
            &FakeOtpPrompt::from_submitted([TEST_OTP]),
            &StormshieldOtpReuseGuard::new(),
            &trust_rejecting(),
            &provider,
            settings,
        )
        .await
        .err()
        .expect("expected establishment failure");

        assert!(error.to_string().contains("injected provider failure"));
        assert_eq!(cache.delete_calls(), 1, "unconfirmed profile must be dropped");
        assert!(cache.entry(&config_id()).is_none());
    }

    #[test]
    fn otp_reuse_guard_rejects_within_window() {
        let clock = Arc::new(Mutex::new(Utc::now()));
        let guard_clock = {
            let clock = clock.clone();
            move || *clock.lock().unwrap_or_else(|p| p.into_inner())
        };
        let guard = StormshieldOtpReuseGuard::new().with_clock(guard_clock);
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
    fn otp_reuse_guard_ignores_blank_and_scopes_by_tunnel() {
        let guard = StormshieldOtpReuseGuard::new();

        guard.record(config_id(), &OtpCode::new("   "));
        assert!(guard.check(config_id(), &OtpCode::new("anything")).is_ok());

        guard.record(config_id(), &OtpCode::new("999999"));
        assert!(guard.check(config_id_2(), &OtpCode::new("999999")).is_ok(), "per-tunnel scope");
        assert!(guard.check(config_id(), &OtpCode::new("999999")).is_err());
    }

    #[test]
    fn cache_record_is_current_accepts_fresh_identical() {
        let settings = settings();
        let record = current_cache_record(&settings.site_identity_hash());
        assert!(stormshield_cache_record_is_current(
            &record,
            &settings.site_identity_hash(),
            STORMSHIELD_CACHE_MAX_AGE
        ));
    }

    #[test]
    fn extract_ovpn_remote_hosts_parses_remotes_and_skips_noise() {
        let profile = "\
client
remote vpn.example 1194 tcp
; comment remote fake.example
# another comment
<connection>
remote conn-1.example 443 udp
<ca>
remote inside-ca.example
</ca>
</connection>
remote   \"quoted host.example\"  443
remote vpn.example 1194 tcp
<custom-block>
remote custom.example
</custom-block>
remote
dev tun
";
        let hosts = extract_ovpn_remote_hosts(profile);
        assert_eq!(
            hosts,
            vec![
                "vpn.example",
                "conn-1.example",
                "quoted host.example",
                "custom.example"
            ]
        );
    }

    #[test]
    fn extract_ovpn_remote_hosts_normalizes_crlf_and_cr() {
        let hosts = extract_ovpn_remote_hosts("client\r\nremote crlf.example\r\nremote cr.example\rdev tun\r\n");
        assert_eq!(hosts, vec!["crlf.example", "cr.example"]);
    }

    #[test]
    fn extract_ovpn_remote_hosts_empty_without_usable_remote() {
        assert!(extract_ovpn_remote_hosts("").is_empty());
        assert!(extract_ovpn_remote_hosts("client\ndev tun\n").is_empty());
        assert!(extract_ovpn_remote_hosts("client\nremote \n").is_empty());
        assert!(extract_ovpn_remote_hosts("<ca>\nremote fake.example\n</ca>\nclient\n").is_empty());
        assert!(extract_ovpn_remote_hosts("remote  \nclient\n").is_empty());
    }

    #[test]
    fn looks_like_openvpn_profile_marker_gate() {
        assert!(looks_like_openvpn_profile("client\nremote x.example\n<ca>\n"));
        assert!(looks_like_openvpn_profile("client\nremote x.example 443\ndev tun\n"));
        assert!(looks_like_openvpn_profile("client\nremote x.example\ndev tap0\n"));
        assert!(!looks_like_openvpn_profile("client\nremote x.example\n"));
        assert!(!looks_like_openvpn_profile("<html>remote login failed</html>"));
        assert!(!looks_like_openvpn_profile("   "));
    }

    #[test]
    fn require_physical_path_fails_closed_on_empty_hosts() {
        let probe = ethernet_probe();
        let error = require_physical_path("lab", &probe, &[], "transport").unwrap_err();
        assert!(
            error.to_string().contains("destination is empty"),
            "unexpected: {error}"
        );
    }

    #[test]
    fn cache_record_is_current_fail_closed_table() {
        let settings = settings();
        let good = current_cache_record(&settings.site_identity_hash());

        let mut wrong_schema = good.clone();
        wrong_schema.schema_version = 2;
        assert!(!stormshield_cache_record_is_current(
            &wrong_schema,
            &settings.site_identity_hash(),
            STORMSHIELD_CACHE_MAX_AGE
        ));

        let mut empty_profile = good.clone();
        empty_profile.profile_ovpn = "  ".to_string();
        assert!(!stormshield_cache_record_is_current(
            &empty_profile,
            &settings.site_identity_hash(),
            STORMSHIELD_CACHE_MAX_AGE
        ));

        let mut empty_identity = good.clone();
        empty_identity.site_identity_hash = "  ".to_string();
        assert!(!stormshield_cache_record_is_current(
            &empty_identity,
            &settings.site_identity_hash(),
            STORMSHIELD_CACHE_MAX_AGE
        ));

        let mut mismatched = good.clone();
        mismatched.site_identity_hash = "OTHER".to_string();
        assert!(!stormshield_cache_record_is_current(
            &mismatched,
            &settings.site_identity_hash(),
            STORMSHIELD_CACHE_MAX_AGE
        ));

        let mut stale = good.clone();
        stale.cached_at_utc = (Utc::now() - chrono::Duration::days(8))
            .to_rfc3339_opts(SecondsFormat::Secs, true);
        assert!(!stormshield_cache_record_is_current(
            &stale,
            &settings.site_identity_hash(),
            STORMSHIELD_CACHE_MAX_AGE
        ));

        let mut future = good.clone();
        future.cached_at_utc = (Utc::now() + chrono::Duration::hours(1))
            .to_rfc3339_opts(SecondsFormat::Secs, true);
        assert!(!stormshield_cache_record_is_current(
            &future,
            &settings.site_identity_hash(),
            STORMSHIELD_CACHE_MAX_AGE
        ));

        let mut unparseable = good.clone();
        unparseable.cached_at_utc = "not-a-date".to_string();
        assert!(!stormshield_cache_record_is_current(
            &unparseable,
            &settings.site_identity_hash(),
            STORMSHIELD_CACHE_MAX_AGE
        ));

        assert!(!stormshield_cache_record_is_current(
            &good,
            &settings.site_identity_hash(),
            Duration::ZERO
        ));
    }

    #[test]
    fn encode_stormshield_cache_record_roundtrips_pascal_case() {
        let record = current_cache_record("IDENT");
        let json = encode_stormshield_cache_record(&record).unwrap();
        let decoded = decode_stormshield_cache_json(&json).unwrap();
        assert_eq!(decoded, record);

        let text = String::from_utf8(json).unwrap();
        assert!(text.contains("\"SchemaVersion\""), "PascalCase expected: {text}");
        assert!(!text.contains("schemaVersion"), "PascalCase expected: {text}");
    }

    #[test]
    fn encode_stormshield_cache_record_rejects_bad_shape() {
        let mut record = current_cache_record("IDENT");
        record.schema_version = 99;
        assert!(encode_stormshield_cache_record(&record).is_err());

        record.schema_version = STORM_SHIELD_CACHE_SCHEMA;
        record.profile_ovpn = " ".to_string();
        assert!(encode_stormshield_cache_record(&record).is_err());
    }

    #[test]
    fn site_identity_hash_excludes_password_but_includes_trust() {
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

        let app_token_override = settings().with_app_token("custom");
        assert_ne!(base.site_identity_hash(), app_token_override.site_identity_hash());

        let blank_token_falls_back = settings().with_app_token("  ");
        assert_eq!(base.site_identity_hash(), blank_token_falls_back.site_identity_hash());
    }

    #[test]
    fn debug_never_prints_secrets() {
        let settings = settings();
        let debug = format!("{settings:?}");
        assert!(!debug.contains(TEST_PASSWORD));
        assert!(!debug.contains(TEST_OTP));

        let call = StormshieldPortalFetchCall::new(
            StormshieldPortalRequest::new(TEST_SERVER, 443),
            TEST_USERNAME,
            TEST_PASSWORD,
        );
        let debug = format!("{call:?}");
        assert!(!debug.contains(TEST_PASSWORD));
        assert!(debug.contains("[REDACTED]"));

        let failure = StormshieldTlsFailure::new("CN=fw.example", "CN=Lab Root CA", TEST_THUMBPRINT);
        let debug = format!("{failure:?}");
        assert!(!debug.contains(TEST_THUMBPRINT));
        assert!(debug.contains("thumbprint_prefix"));

        let outcome = AutomaticOutcome {
            profile_ovpn: TEST_PROFILE.to_string(),
            data_plane_password: "s3cret654321".to_string(),
            optimistic_cache_hit: false,
        };
        let debug = format!("{outcome:?}");
        assert!(!debug.contains("s3cret654321"));
        assert!(!debug.contains(TEST_PROFILE));

        let cache = MemoryStormshieldProfileCache::new();
        cache.seed(config_id(), current_cache_record("IDENT"));
        let debug = format!("{cache:?}");
        assert!(!debug.contains("IDENT"));
        assert!(!debug.contains("vpn.example"));
    }
}

