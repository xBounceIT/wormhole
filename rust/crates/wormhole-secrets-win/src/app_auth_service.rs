//! App PIN / password verifier glue over an injectable protector.
//!
//! Mirrors C# `AppAuthenticationService` + `IAppAuthenticationDataProtector`:
//! PBKDF2-SHA256 verifiers in a JSON document, protected for the
//! `app-auth.dpapi` store. Interactive Windows Hello stays in [`crate::hello`]
//! / `wormhole-app::hello_unlock` — this module covers **Disabled / Pin /
//! Password** set · verify · clear only.
//!
//! Unit tests inject [`FakeAppAuthenticationDataProtector`] (pass-through; no
//! live DPAPI). Production can wrap [`DpapiAppAuthenticationDataProtector`].
//!
//! **Never** log PIN / password plaintext or verifier salt/hash bytes.
//! [`Debug`] on service / Fake / status types exposes lengths and flags only.

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use pbkdf2::pbkdf2_hmac;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::app_auth::{protect_app_authentication, unprotect_app_authentication};
use crate::dpapi::{delete_protected_file_if_exists, replace_file};
use crate::paths::app_authentication_path;
use crate::{Result, SecretsError};

/// Default PBKDF2 iteration count (C# `AppAuthenticationService.DefaultPbkdf2Iterations`).
pub const DEFAULT_PBKDF2_ITERATIONS: u32 = 600_000;

/// Upper bound for stored / configured PBKDF2 iterations.
///
/// Shipping C# always writes [`DEFAULT_PBKDF2_ITERATIONS`]. Anything higher is
/// treated as an invalid verifier shape (fail closed) so a hostile
/// `app-auth.dpapi` cannot force multi-hour unlock work.
pub const MAX_PBKDF2_ITERATIONS: u32 = DEFAULT_PBKDF2_ITERATIONS;

const SALT_LENGTH: usize = 16;
const HASH_LENGTH: usize = 32;
const PIN_MIN_LENGTH: usize = 4;
const PIN_MAX_LENGTH: usize = 12;
const PASSWORD_MIN_LENGTH: usize = 8;
const PASSWORD_MAX_LENGTH: usize = 128;

/// App lock mode (C# `AppAuthenticationMode`) — Hello is stubbed elsewhere.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AppAuthenticationMode {
    /// No app lock.
    Disabled,
    /// Unlock with Wormhole PIN.
    Pin,
    /// Unlock with Wormhole password.
    Password,
    /// Windows Hello (+ PIN/password fallback). Interactive Hello is **not**
    /// driven by this service — use [`crate::hello`] / `hello_unlock`.
    WindowsHello,
}

/// Which secret slot to set / verify (C# `AppAuthenticationFallbackMethod`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AppAuthenticationMethod {
    /// Digit PIN (4–12 ASCII digits).
    Pin,
    /// Password (8–128 UTF-16 code units).
    Password,
}

/// Status of the verifier store (C# `AppAuthenticationSecretStatus`).
///
/// [`Debug`] never echoes salt/hash/plaintext — flags only.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct AppAuthenticationSecretStatus {
    /// Whether a PIN verifier is present.
    pub has_pin: bool,
    /// Whether a password verifier is present.
    pub has_password: bool,
    /// Store present but unreadable / invalid JSON / bad verifier shape.
    pub is_corrupted: bool,
}

impl fmt::Debug for AppAuthenticationSecretStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AppAuthenticationSecretStatus")
            .field("has_pin", &self.has_pin)
            .field("has_password", &self.has_password)
            .field("is_corrupted", &self.is_corrupted)
            .finish()
    }
}

/// Result of [`AppAuthenticationService::validate_secret`] (never embeds the secret).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppAuthenticationSecretValidation {
    /// Whether the candidate meets length / charset rules.
    pub is_valid: bool,
    /// Fixed UI copy when invalid; `None` when valid. Never the secret.
    pub error: Option<&'static str>,
}

impl AppAuthenticationSecretValidation {
    fn ok() -> Self {
        Self {
            is_valid: true,
            error: None,
        }
    }

    fn err(error: &'static str) -> Self {
        Self {
            is_valid: false,
            error: Some(error),
        }
    }
}

/// Protect / unprotect the app-auth verifier document (C# `IAppAuthenticationDataProtector`).
///
/// Implementations must **never** log plaintext. Tests use
/// [`FakeAppAuthenticationDataProtector`]; production uses
/// [`DpapiAppAuthenticationDataProtector`].
pub trait AppAuthenticationDataProtector: Send + Sync {
    /// Protect verifier JSON bytes.
    fn protect(&self, plaintext: &[u8]) -> Result<Vec<u8>>;

    /// Unprotect a blob. Corrupt / wrong entropy → error (fail closed).
    fn unprotect(&self, blob: &[u8]) -> Result<Vec<u8>>;
}

/// Production protector: CurrentUser DPAPI + [`crate::APP_AUTHENTICATION_V1`].
#[derive(Default)]
pub struct DpapiAppAuthenticationDataProtector;

impl fmt::Debug for DpapiAppAuthenticationDataProtector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DpapiAppAuthenticationDataProtector")
    }
}

impl DpapiAppAuthenticationDataProtector {
    /// Construct the DPAPI protector.
    pub fn new() -> Self {
        Self
    }
}

impl AppAuthenticationDataProtector for DpapiAppAuthenticationDataProtector {
    fn protect(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        protect_app_authentication(plaintext)
    }

    fn unprotect(&self, blob: &[u8]) -> Result<Vec<u8>> {
        unprotect_app_authentication(blob)
    }
}

/// Pass-through protector for unit tests (C# `PassThroughProtector`).
///
/// No live DPAPI. [`Debug`] exposes call counts only — never blob bytes.
#[derive(Default)]
pub struct FakeAppAuthenticationDataProtector {
    protect_calls: AtomicUsize,
    unprotect_calls: AtomicUsize,
}

impl fmt::Debug for FakeAppAuthenticationDataProtector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FakeAppAuthenticationDataProtector")
            .field("protect_calls", &self.protect_calls.load(Ordering::Relaxed))
            .field(
                "unprotect_calls",
                &self.unprotect_calls.load(Ordering::Relaxed),
            )
            .finish()
    }
}

impl FakeAppAuthenticationDataProtector {
    /// Empty Fake protector.
    pub fn new() -> Self {
        Self::default()
    }

    /// How many times [`AppAuthenticationDataProtector::protect`] was called.
    pub fn protect_calls(&self) -> usize {
        self.protect_calls.load(Ordering::Relaxed)
    }

    /// How many times [`AppAuthenticationDataProtector::unprotect`] was called.
    pub fn unprotect_calls(&self) -> usize {
        self.unprotect_calls.load(Ordering::Relaxed)
    }
}

impl AppAuthenticationDataProtector for FakeAppAuthenticationDataProtector {
    fn protect(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        self.protect_calls.fetch_add(1, Ordering::Relaxed);
        // Defensive copy — caller may zeroize after protect.
        Ok(plaintext.to_vec())
    }

    fn unprotect(&self, blob: &[u8]) -> Result<Vec<u8>> {
        self.unprotect_calls.fetch_add(1, Ordering::Relaxed);
        Ok(blob.to_vec())
    }
}

#[derive(Serialize, Deserialize)]
struct AppAuthenticationDocument {
    #[serde(rename = "Version")]
    version: i32,
    #[serde(rename = "Pin", default)]
    pin: Option<AppAuthenticationVerifierJson>,
    #[serde(rename = "Password", default)]
    password: Option<AppAuthenticationVerifierJson>,
}

impl Default for AppAuthenticationDocument {
    fn default() -> Self {
        Self {
            version: 1,
            pin: None,
            password: None,
        }
    }
}

#[derive(Serialize, Deserialize)]
struct AppAuthenticationVerifierJson {
    #[serde(rename = "Salt", with = "serde_b64")]
    salt: Vec<u8>,
    #[serde(rename = "Hash", with = "serde_b64")]
    hash: Vec<u8>,
    #[serde(rename = "Iterations")]
    iterations: i32,
}

mod serde_b64 {
    use base64::Engine;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error> {
        let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
        serializer.serialize_str(&encoded)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(deserializer)?;
        base64::engine::general_purpose::STANDARD
            .decode(s.as_bytes())
            .map_err(serde::de::Error::custom)
    }
}

/// PIN / password set · verify · clear over a protector + store path.
///
/// Mirrors C# `AppAuthenticationService`. [`Debug`] never echoes secrets —
/// path length, iteration count, and call-safe flags only.
pub struct AppAuthenticationService {
    store_path: PathBuf,
    pbkdf2_iterations: u32,
    protector: Box<dyn AppAuthenticationDataProtector>,
    gate: Mutex<()>,
}

impl fmt::Debug for AppAuthenticationService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AppAuthenticationService")
            .field("store_path_len", &self.store_path.as_os_str().len())
            .field("pbkdf2_iterations", &self.pbkdf2_iterations)
            .finish_non_exhaustive()
    }
}

impl AppAuthenticationService {
    /// Production defaults: `%LOCALAPPDATA%\Wormhole\app-auth.dpapi` + DPAPI protector.
    pub fn new() -> Self {
        Self::with_protector(
            app_authentication_path(),
            DEFAULT_PBKDF2_ITERATIONS,
            Box::new(DpapiAppAuthenticationDataProtector::new()),
        )
    }

    /// Injectable path / iterations / protector (tests: Fake + tempfile + low iterations).
    ///
    /// `pbkdf2_iterations` must be in `1..=MAX_PBKDF2_ITERATIONS` — panics
    /// otherwise. The lower bound matches C#
    /// `ArgumentOutOfRangeException.ThrowIfNegativeOrZero`; the upper bound
    /// keeps JSON `Iterations` in `i32` range and caps hostile DoS work.
    pub fn with_protector(
        store_path: impl Into<PathBuf>,
        pbkdf2_iterations: u32,
        protector: Box<dyn AppAuthenticationDataProtector>,
    ) -> Self {
        assert!(
            (1..=MAX_PBKDF2_ITERATIONS).contains(&pbkdf2_iterations),
            "pbkdf2_iterations must be in 1..=MAX_PBKDF2_ITERATIONS"
        );
        Self {
            store_path: store_path.into(),
            pbkdf2_iterations,
            protector,
            gate: Mutex::new(()),
        }
    }

    /// Convenience: Fake protector + path + low iterations for unit tests.
    pub fn with_fake_protector(store_path: impl Into<PathBuf>, pbkdf2_iterations: u32) -> Self {
        Self::with_protector(
            store_path,
            pbkdf2_iterations,
            Box::new(FakeAppAuthenticationDataProtector::new()),
        )
    }

    /// Store path used by this service.
    pub fn store_path(&self) -> &Path {
        &self.store_path
    }

    /// Validate PIN / password shape without touching the store.
    ///
    /// **Never** log `secret`.
    pub fn validate_secret(
        &self,
        method: AppAuthenticationMethod,
        secret: &str,
    ) -> AppAuthenticationSecretValidation {
        match method {
            AppAuthenticationMethod::Pin => validate_pin(secret),
            AppAuthenticationMethod::Password => validate_password(secret),
        }
    }

    /// Read whether PIN / password verifiers exist (corrupt → flags only).
    pub fn status(&self) -> Result<AppAuthenticationSecretStatus> {
        let _guard = self.gate.lock().unwrap_or_else(|p| p.into_inner());
        let (doc, corrupted) = self.read_document()?;
        Ok(AppAuthenticationSecretStatus {
            has_pin: doc.pin.is_some(),
            has_password: doc.password.is_some(),
            is_corrupted: corrupted,
        })
    }

    /// Whether the configured mode has a usable verifier (Hello not probed here).
    pub fn is_configured_for_mode(
        &self,
        mode: AppAuthenticationMode,
        fallback: AppAuthenticationMethod,
    ) -> Result<bool> {
        if mode == AppAuthenticationMode::Disabled {
            return Ok(false);
        }
        let status = self.status()?;
        if status.is_corrupted {
            return Ok(false);
        }
        Ok(match mode {
            AppAuthenticationMode::Disabled => false,
            AppAuthenticationMode::Pin => status.has_pin,
            AppAuthenticationMode::Password => status.has_password,
            AppAuthenticationMode::WindowsHello => match fallback {
                AppAuthenticationMethod::Pin => status.has_pin,
                AppAuthenticationMethod::Password => status.has_password,
            },
        })
    }

    /// Create / overwrite a PIN or password verifier.
    ///
    /// Invalid shape → [`SecretsError::InvalidAppAuthSecret`] (message never
    /// embeds the secret). Overwrites a corrupted store on success.
    pub fn set_secret(&self, method: AppAuthenticationMethod, secret: &str) -> Result<()> {
        let validation = self.validate_secret(method, secret);
        if !validation.is_valid {
            return Err(SecretsError::InvalidAppAuthSecret {
                reason: validation.error.unwrap_or("Invalid secret."),
            });
        }

        let _guard = self.gate.lock().unwrap_or_else(|p| p.into_inner());
        let (mut doc, _) = self.read_document()?;
        let verifier = create_verifier(secret, self.pbkdf2_iterations)?;
        match method {
            AppAuthenticationMethod::Pin => doc.pin = Some(verifier),
            AppAuthenticationMethod::Password => doc.password = Some(verifier),
        }
        doc.version = 1;
        self.write_document(&doc)
    }

    /// Verify a candidate against the stored verifier. Wrong / missing /
    /// corrupted → `Ok(false)` (fail closed). **Never** log `secret`.
    pub fn verify_secret(&self, method: AppAuthenticationMethod, secret: &str) -> Result<bool> {
        let _guard = self.gate.lock().unwrap_or_else(|p| p.into_inner());
        let (doc, corrupted) = self.read_document()?;
        if corrupted {
            return Ok(false);
        }
        let verifier = match method {
            AppAuthenticationMethod::Pin => doc.pin.as_ref(),
            AppAuthenticationMethod::Password => doc.password.as_ref(),
        };
        Ok(match verifier {
            Some(v) => verify(secret, v),
            None => false,
        })
    }

    /// Mode-aware unlock without Hello UI:
    /// - [`AppAuthenticationMode::Disabled`] → `true`
    /// - Pin / Password → [`verify_secret`] for that method
    /// - WindowsHello → verify the **fallback** method only (Hello is stubbed
    ///   separately; this never claims biometric success)
    pub fn verify_for_mode(
        &self,
        mode: AppAuthenticationMode,
        fallback: AppAuthenticationMethod,
        secret: &str,
    ) -> Result<bool> {
        match mode {
            AppAuthenticationMode::Disabled => Ok(true),
            AppAuthenticationMode::Pin => self.verify_secret(AppAuthenticationMethod::Pin, secret),
            AppAuthenticationMode::Password => {
                self.verify_secret(AppAuthenticationMethod::Password, secret)
            }
            AppAuthenticationMode::WindowsHello => self.verify_secret(fallback, secret),
        }
    }

    /// Delete the store file (missing → `Ok(())`).
    pub fn clear(&self) -> Result<()> {
        let _guard = self.gate.lock().unwrap_or_else(|p| p.into_inner());
        delete_protected_file_if_exists(&self.store_path)
    }

    fn read_document(&self) -> Result<(AppAuthenticationDocument, bool)> {
        let protected = match std::fs::read(&self.store_path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok((AppAuthenticationDocument::default(), false));
            }
            Err(e) => return Err(SecretsError::Io(e)),
        };

        let plaintext = match self.protector.unprotect(&protected) {
            Ok(p) => p,
            Err(_) => {
                // Wrong entropy / corrupt protector → treat as corrupted (fail closed).
                return Ok((AppAuthenticationDocument::default(), true));
            }
        };

        let plaintext = Zeroizing::new(plaintext);
        match serde_json::from_slice::<AppAuthenticationDocument>(plaintext.as_slice()) {
            Ok(doc) if doc.version == 1 && is_valid_verifier_shape(&doc.pin) && is_valid_verifier_shape(&doc.password) => {
                Ok((doc, false))
            }
            _ => Ok((AppAuthenticationDocument::default(), true)),
        }
    }

    fn write_document(&self, doc: &AppAuthenticationDocument) -> Result<()> {
        if let Some(parent) = self.store_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        // Pretty JSON matches C# `WriteIndented = true` for dual-host friendliness.
        let plaintext = Zeroizing::new(
            serde_json::to_vec_pretty(doc).map_err(|_| SecretsError::InvalidAppAuthSecret {
                reason: "Failed to serialize app authentication document.",
            })?,
        );
        let protected = self.protector.protect(plaintext.as_slice())?;
        // Atomic sibling temp (same pattern as `write_protected_file_atomic` /
        // Azure caches): `path + "." + Guid.N + ".tmp"`. Shipping C#
        // `AppAuthenticationService` uses a fixed `path + ".tmp"`; the Guid form
        // avoids collisions under concurrent writers.
        let mut tmp_os = self.store_path.as_os_str().to_owned();
        tmp_os.push(".");
        tmp_os.push(uuid::Uuid::new_v4().simple().to_string());
        tmp_os.push(".tmp");
        let temp_path = PathBuf::from(tmp_os);
        let result = (|| -> Result<()> {
            std::fs::write(&temp_path, &protected)?;
            replace_file(&temp_path, &self.store_path)?;
            Ok(())
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&temp_path);
        }
        result
    }
}

impl Default for AppAuthenticationService {
    fn default() -> Self {
        Self::new()
    }
}

fn validate_pin(pin: &str) -> AppAuthenticationSecretValidation {
    let len = utf16_len(pin);
    if !(PIN_MIN_LENGTH..=PIN_MAX_LENGTH).contains(&len) {
        return AppAuthenticationSecretValidation::err("PIN must be 4 to 12 digits.");
    }
    if !pin.chars().all(|c| c.is_ascii_digit()) {
        return AppAuthenticationSecretValidation::err("PIN can contain digits only.");
    }
    AppAuthenticationSecretValidation::ok()
}

fn validate_password(password: &str) -> AppAuthenticationSecretValidation {
    let len = utf16_len(password);
    if !(PASSWORD_MIN_LENGTH..=PASSWORD_MAX_LENGTH).contains(&len) {
        return AppAuthenticationSecretValidation::err(
            "Password must be 8 to 128 characters.",
        );
    }
    AppAuthenticationSecretValidation::ok()
}

/// C# `string.Length` is UTF-16 code units.
fn utf16_len(s: &str) -> usize {
    s.encode_utf16().count()
}

fn is_valid_verifier_shape(verifier: &Option<AppAuthenticationVerifierJson>) -> bool {
    match verifier {
        None => true,
        Some(v) => verifier_shape_ok(v),
    }
}

fn verifier_shape_ok(verifier: &AppAuthenticationVerifierJson) -> bool {
    verifier.iterations > 0
        && (verifier.iterations as u32) <= MAX_PBKDF2_ITERATIONS
        && verifier.salt.len() == SALT_LENGTH
        && verifier.hash.len() == HASH_LENGTH
}

fn create_verifier(secret: &str, iterations: u32) -> Result<AppAuthenticationVerifierJson> {
    // Constructor already caps `iterations` to `MAX_PBKDF2_ITERATIONS` (≤ i32::MAX).
    let iterations_i32 = iterations as i32;
    let mut salt = vec![0u8; SALT_LENGTH];
    getrandom::fill(&mut salt).map_err(|_| SecretsError::InvalidAppAuthSecret {
        reason: "Failed to generate salt.",
    })?;
    let hash = derive(secret, &salt, iterations);
    Ok(AppAuthenticationVerifierJson {
        salt,
        hash,
        iterations: iterations_i32,
    })
}

fn verify(secret: &str, verifier: &AppAuthenticationVerifierJson) -> bool {
    if !verifier_shape_ok(verifier) {
        return false;
    }
    let iterations = verifier.iterations as u32;
    let hash = Zeroizing::new(derive(secret, &verifier.salt, iterations));
    fixed_time_eq(hash.as_slice(), &verifier.hash)
}

fn derive(secret: &str, salt: &[u8], iterations: u32) -> Vec<u8> {
    let mut out = vec![0u8; HASH_LENGTH];
    // UTF-8 bytes of the secret — parity with C# Encoding.UTF8.GetBytes.
    pbkdf2_hmac::<Sha256>(secret.as_bytes(), salt, iterations, &mut out);
    out
}

fn fixed_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn temp_service(iterations: u32) -> (tempfile::TempDir, AppAuthenticationService) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("app-auth.dpapi");
        let service = AppAuthenticationService::with_fake_protector(path, iterations);
        (dir, service)
    }

    #[test]
    fn validate_pin_range_and_digits() {
        let (_dir, svc) = temp_service(1_000);
        assert!(!svc.validate_secret(AppAuthenticationMethod::Pin, "").is_valid);
        assert!(!svc.validate_secret(AppAuthenticationMethod::Pin, "123").is_valid);
        assert!(svc.validate_secret(AppAuthenticationMethod::Pin, "1234").is_valid);
        assert!(
            svc.validate_secret(AppAuthenticationMethod::Pin, "123456789012")
                .is_valid
        );
        assert!(
            !svc.validate_secret(AppAuthenticationMethod::Pin, "1234567890123")
                .is_valid
        );
        assert!(!svc.validate_secret(AppAuthenticationMethod::Pin, "12a4").is_valid);
        // Validation error never embeds the candidate.
        let v = svc.validate_secret(AppAuthenticationMethod::Pin, "12a4-secret");
        assert!(!format!("{v:?}").contains("12a4-secret"));
    }

    #[test]
    fn validate_password_range() {
        let (_dir, svc) = temp_service(1_000);
        assert!(
            !svc.validate_secret(AppAuthenticationMethod::Password, "short")
                .is_valid
        );
        assert!(
            svc.validate_secret(AppAuthenticationMethod::Password, "12345678")
                .is_valid
        );
    }

    #[test]
    fn set_and_verify_pin_wrong_secret_fails_closed() {
        let (_dir, svc) = temp_service(1_000);
        svc.set_secret(AppAuthenticationMethod::Pin, "123456")
            .unwrap();

        assert!(
            svc.verify_secret(AppAuthenticationMethod::Pin, "123456")
                .unwrap()
        );
        assert!(
            !svc
                .verify_secret(AppAuthenticationMethod::Pin, "654321")
                .unwrap()
        );
        // Wrong method slot fails closed.
        assert!(
            !svc
                .verify_secret(AppAuthenticationMethod::Password, "123456")
                .unwrap()
        );
    }

    #[test]
    fn set_and_verify_password_wrong_secret_fails_closed() {
        let (_dir, svc) = temp_service(1_000);
        svc.set_secret(AppAuthenticationMethod::Password, "correct horse")
            .unwrap();

        assert!(
            svc.verify_secret(AppAuthenticationMethod::Password, "correct horse")
                .unwrap()
        );
        assert!(
            !svc
                .verify_secret(AppAuthenticationMethod::Password, "battery staple")
                .unwrap()
        );
    }

    #[test]
    fn missing_store_reports_no_secrets() {
        let (_dir, svc) = temp_service(1_000);
        let status = svc.status().unwrap();
        assert!(!status.has_pin);
        assert!(!status.has_password);
        assert!(!status.is_corrupted);
    }

    #[test]
    fn corrupted_store_reports_corruption_and_rejects_verification() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("app-auth.dpapi");
        std::fs::write(&path, b"not-json").unwrap();
        let svc = AppAuthenticationService::with_fake_protector(&path, 1_000);

        let status = svc.status().unwrap();
        assert!(status.is_corrupted);
        assert!(
            !svc
                .verify_secret(AppAuthenticationMethod::Pin, "1234")
                .unwrap()
        );
    }

    #[test]
    fn set_secret_overwrites_corrupted_store() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("app-auth.dpapi");
        std::fs::write(&path, b"not-json").unwrap();
        let svc = AppAuthenticationService::with_fake_protector(&path, 1_000);

        svc.set_secret(AppAuthenticationMethod::Pin, "1234").unwrap();
        let status = svc.status().unwrap();
        assert!(status.has_pin);
        assert!(!status.is_corrupted);
        assert!(svc.verify_secret(AppAuthenticationMethod::Pin, "1234").unwrap());
    }

    #[test]
    fn clear_removes_verifiers() {
        let (_dir, svc) = temp_service(1_000);
        svc.set_secret(AppAuthenticationMethod::Pin, "1234").unwrap();
        svc.set_secret(AppAuthenticationMethod::Password, "password1")
            .unwrap();
        svc.clear().unwrap();
        let status = svc.status().unwrap();
        assert!(!status.has_pin);
        assert!(!status.has_password);
        assert!(!status.is_corrupted);
        assert!(
            !svc
                .verify_secret(AppAuthenticationMethod::Pin, "1234")
                .unwrap()
        );
    }

    #[test]
    fn modes_disabled_pin_password_and_hello_fallback_slot() {
        let (_dir, svc) = temp_service(1_000);
        assert!(
            !svc
                .is_configured_for_mode(
                    AppAuthenticationMode::Disabled,
                    AppAuthenticationMethod::Pin
                )
                .unwrap()
        );
        assert!(
            !svc
                .is_configured_for_mode(AppAuthenticationMode::Pin, AppAuthenticationMethod::Pin)
                .unwrap()
        );

        svc.set_secret(AppAuthenticationMethod::Pin, "9999").unwrap();
        assert!(
            svc.is_configured_for_mode(AppAuthenticationMode::Pin, AppAuthenticationMethod::Pin)
                .unwrap()
        );
        assert!(
            !svc
                .is_configured_for_mode(
                    AppAuthenticationMode::Password,
                    AppAuthenticationMethod::Password
                )
                .unwrap()
        );
        assert!(
            svc.is_configured_for_mode(
                AppAuthenticationMode::WindowsHello,
                AppAuthenticationMethod::Pin
            )
            .unwrap()
        );
        assert!(
            !svc
                .is_configured_for_mode(
                    AppAuthenticationMode::WindowsHello,
                    AppAuthenticationMethod::Password
                )
                .unwrap()
        );

        // Disabled always verifies true; wrong PIN fails closed for Pin mode.
        assert!(
            svc.verify_for_mode(
                AppAuthenticationMode::Disabled,
                AppAuthenticationMethod::Pin,
                "anything"
            )
            .unwrap()
        );
        assert!(
            !svc
                .verify_for_mode(
                    AppAuthenticationMode::Pin,
                    AppAuthenticationMethod::Pin,
                    "0000"
                )
                .unwrap()
        );
        assert!(
            svc.verify_for_mode(
                AppAuthenticationMode::Pin,
                AppAuthenticationMethod::Pin,
                "9999"
            )
            .unwrap()
        );
    }

    #[test]
    fn set_invalid_secret_fails_without_echoing() {
        let (_dir, svc) = temp_service(1_000);
        let err = svc
            .set_secret(AppAuthenticationMethod::Pin, "bad-pin-xyz")
            .unwrap_err();
        let text = format!("{err} / {err:?}");
        assert!(matches!(err, SecretsError::InvalidAppAuthSecret { .. }));
        assert!(!text.contains("bad-pin-xyz"));
        assert!(!text.contains("xyz"));
    }

    #[test]
    fn debug_never_echoes_secrets_or_verifier_material() {
        let (_dir, svc) = temp_service(1_000);
        let secret = "super-secret-pin-hash-material-9999";
        // Use password path so the secret string can include letters.
        svc.set_secret(AppAuthenticationMethod::Password, "correct horse battery")
            .unwrap();
        let dbg = format!("{svc:?}");
        assert!(!dbg.contains("correct horse"));
        assert!(!dbg.contains("battery"));
        assert!(dbg.contains("pbkdf2_iterations"));

        let status = svc.status().unwrap();
        assert!(!format!("{status:?}").contains("correct"));

        let fake = FakeAppAuthenticationDataProtector::new();
        let _ = fake.protect(secret.as_bytes()).unwrap();
        let fake_dbg = format!("{fake:?}");
        assert!(!fake_dbg.contains("super-secret"));
        assert!(!fake_dbg.contains("pin-hash"));
        assert!(fake_dbg.contains("protect_calls"));
    }

    #[test]
    fn fake_protector_is_pass_through_and_counted() {
        let fake = FakeAppAuthenticationDataProtector::new();
        let blob = fake.protect(b"verifier-json").unwrap();
        assert_eq!(blob, b"verifier-json");
        assert_eq!(fake.unprotect(&blob).unwrap(), b"verifier-json");
        assert_eq!(fake.protect_calls(), 1);
        assert_eq!(fake.unprotect_calls(), 1);
    }

    #[test]
    fn pin_and_password_slots_are_independent() {
        let (_dir, svc) = temp_service(1_000);
        svc.set_secret(AppAuthenticationMethod::Pin, "1111").unwrap();
        svc.set_secret(AppAuthenticationMethod::Password, "password1")
            .unwrap();
        assert!(svc.verify_secret(AppAuthenticationMethod::Pin, "1111").unwrap());
        assert!(
            svc.verify_secret(AppAuthenticationMethod::Password, "password1")
                .unwrap()
        );
        assert!(
            !svc
                .verify_secret(AppAuthenticationMethod::Pin, "password1")
                .unwrap()
        );
    }

    #[test]
    fn concurrent_verify_is_mutex_safe() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("app-auth.dpapi");
        let svc = Arc::new(AppAuthenticationService::with_fake_protector(path, 1_000));
        svc.set_secret(AppAuthenticationMethod::Pin, "4242").unwrap();

        let barrier = Arc::new(std::sync::Barrier::new(4));
        let mut handles = Vec::new();
        for _ in 0..4 {
            let svc = Arc::clone(&svc);
            let barrier = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                assert!(
                    svc.verify_secret(AppAuthenticationMethod::Pin, "4242")
                        .unwrap()
                );
                assert!(
                    !svc
                        .verify_secret(AppAuthenticationMethod::Pin, "0000")
                        .unwrap()
                );
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
    }

    #[test]
    fn document_json_uses_pascal_case_and_base64() {
        let (_dir, svc) = temp_service(1_000);
        svc.set_secret(AppAuthenticationMethod::Pin, "5555").unwrap();
        let raw = std::fs::read(svc.store_path()).unwrap();
        // Fake protector → plaintext JSON on disk.
        let text = String::from_utf8(raw).unwrap();
        assert!(text.contains("\"Version\""));
        assert!(text.contains("\"Pin\""));
        assert!(text.contains("\"Salt\""));
        assert!(text.contains("\"Hash\""));
        assert!(text.contains("\"Iterations\""));
        assert!(!text.contains("5555")); // PIN never stored in clear
    }

    #[test]
    fn password_length_uses_utf16_code_units() {
        let (_dir, svc) = temp_service(1_000);
        // 7 ASCII + one astral emoji = 9 UTF-16 units → valid (≥ 8).
        let short_ok = format!("abcdefg{}", "🔒");
        assert_eq!(utf16_len(&short_ok), 9);
        assert!(
            svc.validate_secret(AppAuthenticationMethod::Password, &short_ok)
                .is_valid
        );

        // 64 emoji = 128 UTF-16 units → at max; 65 emoji = 130 → over.
        let at_max: String = std::iter::repeat_n('🔒', 64).collect();
        assert_eq!(utf16_len(&at_max), PASSWORD_MAX_LENGTH);
        assert!(
            svc.validate_secret(AppAuthenticationMethod::Password, &at_max)
                .is_valid
        );
        let over: String = std::iter::repeat_n('🔒', 65).collect();
        assert_eq!(utf16_len(&over), 130);
        assert!(
            !svc.validate_secret(AppAuthenticationMethod::Password, &over)
                .is_valid
        );
        // Char-count would wrongly accept 100 BMP + reject 64 emoji — pin UTF-16.
        let hundred_ascii: String = std::iter::repeat_n('a', 100).collect();
        assert!(
            svc.validate_secret(AppAuthenticationMethod::Password, &hundred_ascii)
                .is_valid
        );
    }

    #[test]
    fn pin_rejects_non_ascii_digits() {
        let (_dir, svc) = temp_service(1_000);
        // Fullwidth / Arabic-Indic digits are Unicode Nd; Wormhole PIN is ASCII-only.
        assert!(
            !svc.validate_secret(AppAuthenticationMethod::Pin, "１２３４")
                .is_valid
        );
        assert!(
            !svc.validate_secret(AppAuthenticationMethod::Pin, "١٢٣٤")
                .is_valid
        );
    }

    #[test]
    fn hostile_verifier_shape_is_corrupted_and_rejects_verify() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("app-auth.dpapi");
        // 16-byte salt + 32-byte hash (valid lengths) but Iterations at i32::MAX —
        // accepting this would hang unlock (DoS). Shape must reject as corrupted.
        let hostile = concat!(
            "{\n",
            "  \"Version\": 1,\n",
            "  \"Pin\": {\n",
            "    \"Salt\": \"AAAAAAAAAAAAAAAAAAAAAA==\",\n",
            "    \"Hash\": \"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\",\n",
            "    \"Iterations\": 2147483647\n",
            "  },\n",
            "  \"Password\": null\n",
            "}\n",
        );
        std::fs::write(&path, hostile).unwrap();
        let svc = AppAuthenticationService::with_fake_protector(&path, 1_000);

        let status = svc.status().unwrap();
        assert!(status.is_corrupted);
        assert!(!status.has_pin);
        assert!(
            !svc
                .verify_secret(AppAuthenticationMethod::Pin, "1234")
                .unwrap()
        );
    }

    #[test]
    fn wrong_salt_length_verifier_is_corrupted() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("app-auth.dpapi");
        // 8-byte salt (valid base64) — shape must reject.
        let bad = br#"{
  "Version": 1,
  "Pin": {
    "Salt": "AAAAAAAAAAA=",
    "Hash": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    "Iterations": 1000
  }
}"#;
        std::fs::write(&path, bad).unwrap();
        let svc = AppAuthenticationService::with_fake_protector(&path, 1_000);
        assert!(svc.status().unwrap().is_corrupted);
        assert!(!svc.verify_secret(AppAuthenticationMethod::Pin, "1234").unwrap());
    }

    #[test]
    fn protector_unprotect_failure_marks_corrupted() {
        struct FailUnprotect;
        impl AppAuthenticationDataProtector for FailUnprotect {
            fn protect(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
                Ok(plaintext.to_vec())
            }
            fn unprotect(&self, _blob: &[u8]) -> Result<Vec<u8>> {
                Err(SecretsError::DpapiUnprotect)
            }
        }

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("app-auth.dpapi");
        std::fs::write(&path, b"dpapi-looking-blob").unwrap();
        let svc = AppAuthenticationService::with_protector(
            &path,
            1_000,
            Box::new(FailUnprotect),
        );
        let status = svc.status().unwrap();
        assert!(status.is_corrupted);
        assert!(
            !svc
                .verify_secret(AppAuthenticationMethod::Pin, "1234")
                .unwrap()
        );
    }

    #[test]
    fn overwriting_pin_preserves_password_slot() {
        let (_dir, svc) = temp_service(1_000);
        svc.set_secret(AppAuthenticationMethod::Pin, "1111").unwrap();
        svc.set_secret(AppAuthenticationMethod::Password, "password1")
            .unwrap();
        svc.set_secret(AppAuthenticationMethod::Pin, "2222").unwrap();

        assert!(svc.verify_secret(AppAuthenticationMethod::Pin, "2222").unwrap());
        assert!(!svc.verify_secret(AppAuthenticationMethod::Pin, "1111").unwrap());
        assert!(
            svc.verify_secret(AppAuthenticationMethod::Password, "password1")
                .unwrap()
        );
        let status = svc.status().unwrap();
        assert!(status.has_pin && status.has_password && !status.is_corrupted);
    }

    #[test]
    fn clear_missing_store_is_ok() {
        let (_dir, svc) = temp_service(1_000);
        svc.clear().unwrap();
        svc.clear().unwrap();
        let status = svc.status().unwrap();
        assert!(!status.has_pin && !status.has_password && !status.is_corrupted);
    }

    #[test]
    fn max_iterations_constant_matches_default() {
        assert_eq!(MAX_PBKDF2_ITERATIONS, DEFAULT_PBKDF2_ITERATIONS);
        assert_eq!(DEFAULT_PBKDF2_ITERATIONS, 600_000);
    }
}
