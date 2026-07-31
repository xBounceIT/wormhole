//! Credential Manager password store (CRUD glue stub).
//!
//! Mirrors C# `CredentialService.StorePasswordAsync` / `ReadPasswordAsync` /
//! `DeletePasswordAsync` — targets `Wormhole:<guid>` (D-format). Distinct from
//! DPAPI key / tunnel payload files under `keys\` / `tunnels\`.
//!
//! # Surface
//!
//! - Free helpers [`store_password`] / [`read_password`] / [`delete_password`]
//! - DI trait [`PasswordStore`] — production [`WinCredPasswordStore`]; tests
//!   inject [`FakePasswordStore`] (in-memory, no Win32 vault)
//!
//! Both write paths call [`ensure_password_fits_cred_mgr`] **before** any
//! insert / `CredWriteW` (2560 UTF-16-byte ceiling). **Never** log password
//! material — [`FakePasswordStore`] `Debug` exposes lengths / call counts only;
//! [`SecretsError::PasswordTooLarge`] carries size only.

use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use uuid::Uuid;

use crate::{Result, SecretsError};

/// Target / application-name prefix: `Wormhole:<guid>`.
pub const CREDENTIAL_PREFIX: &str = "Wormhole:";

/// CredMgr comment written by `CredentialService.StorePasswordAsync`.
pub const CREDENTIAL_COMMENT: &str = "Wormhole credential";

/// Max `CredentialBlob` size on Windows 7+ (UTF-16 bytes) — Meziantou / CredMgr
/// (`CRED_MAX_CREDENTIAL_BLOB_SIZE` = 5 × 512).
pub const MAX_PASSWORD_UTF16_BYTES: usize = 2560;

/// Fixed CredMgr id for the MCP bearer token (`Services/Mcp/McpServerHost.cs`).
pub const MCP_TOKEN_CREDENTIAL_ID: Uuid = Uuid::from_bytes([
    0xa7, 0xf3, 0xc1, 0xe2, 0x9b, 0x6d, 0x4e, 0x8a, 0xbf, 0x21, 0x7c, 0x0d, 0x2e, 0x5a, 0x4b, 0x91,
]);

/// Builds `Wormhole:<guid>` using .NET default (`D`) string form (lowercase + hyphens).
pub fn credential_target(credential_id: &Uuid) -> String {
    format!("{CREDENTIAL_PREFIX}{credential_id}")
}

/// UTF-16LE byte length of `password` as stored in CredMgr (`encode_utf16` × 2).
///
/// Matches C# `password.Length * sizeof(char)` / `Encoding.Unicode.GetByteCount`.
/// Do **not** use:
/// - `str::len() * 2` — UTF-8 bytes; falsely rejects near-limit BMP (e.g. `é`)
/// - `chars().count() * 2` — Unicode scalars; under-counts surrogate pairs and
///   falsely **accepts** oversize astral-plane secrets (e.g. 641 × 🔒)
#[inline]
pub fn password_utf16_byte_len(password: &str) -> usize {
    password.encode_utf16().count() * 2
}

/// Reject passwords that would exceed CredMgr's 2560 UTF-16-byte blob limit.
///
/// Called **before** any CredMgr write or fake-store insert so oversized secrets
/// never reach the vault. Error carries only the measured byte length — never
/// the password itself.
pub fn ensure_password_fits_cred_mgr(password: &str) -> Result<()> {
    let bytes = password_utf16_byte_len(password);
    if bytes > MAX_PASSWORD_UTF16_BYTES {
        return Err(SecretsError::PasswordTooLarge { bytes });
    }
    Ok(())
}

/// DI surface for CredMgr-compatible password storage (production or test fake).
pub trait PasswordStore {
    /// Store / overwrite a password under `Wormhole:<id>`.
    fn store(&self, credential_id: &Uuid, password: &str) -> Result<()>;

    /// Read a password; `Ok(None)` when the target is missing.
    fn read(&self, credential_id: &Uuid) -> Result<Option<String>>;

    /// Delete a credential. Missing targets succeed (C# best-effort delete).
    fn delete(&self, credential_id: &Uuid) -> Result<()>;
}

/// Production CredMgr backend (`CredWriteW` / `CredReadW` / `CredDeleteW`).
///
/// Thin [`PasswordStore`] adapter: methods forward to [`store_password`] /
/// [`read_password`] / [`delete_password`]. Tests inject [`FakePasswordStore`]
/// instead (same size guard + missing-delete / missing-read contracts).
#[derive(Debug, Default, Clone, Copy)]
pub struct WinCredPasswordStore;

impl PasswordStore for WinCredPasswordStore {
    fn store(&self, credential_id: &Uuid, password: &str) -> Result<()> {
        store_password(credential_id, password)
    }

    fn read(&self, credential_id: &Uuid) -> Result<Option<String>> {
        read_password(credential_id)
    }

    fn delete(&self, credential_id: &Uuid) -> Result<()> {
        delete_password(credential_id)
    }
}

/// In-memory CredMgr stand-in for unit tests (no Win32 vault).
///
/// Enforces the same [`MAX_PASSWORD_UTF16_BYTES`] pre-write guard as production.
/// [`Debug`] exposes only entry counts / call counts / UTF-16 byte lengths —
/// never password contents.
pub struct FakePasswordStore {
    entries: Mutex<HashMap<Uuid, String>>,
    store_calls: AtomicUsize,
    read_calls: AtomicUsize,
    delete_calls: AtomicUsize,
    reject_calls: AtomicUsize,
}

impl Default for FakePasswordStore {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for FakePasswordStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let entries = self.entries.lock().unwrap_or_else(|p| p.into_inner());
        // Lengths only — never dump secret strings into harness / panic output.
        let lengths: Vec<usize> = entries
            .values()
            .map(|pw| password_utf16_byte_len(pw))
            .collect();
        f.debug_struct("FakePasswordStore")
            .field("entry_count", &entries.len())
            .field("entry_utf16_byte_lengths", &lengths)
            .field("store_calls", &self.store_calls.load(Ordering::SeqCst))
            .field("read_calls", &self.read_calls.load(Ordering::SeqCst))
            .field("delete_calls", &self.delete_calls.load(Ordering::SeqCst))
            .field("reject_calls", &self.reject_calls.load(Ordering::SeqCst))
            .finish()
    }
}

impl FakePasswordStore {
    /// Empty memory store.
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            store_calls: AtomicUsize::new(0),
            read_calls: AtomicUsize::new(0),
            delete_calls: AtomicUsize::new(0),
            reject_calls: AtomicUsize::new(0),
        }
    }

    fn entries_guard(&self) -> std::sync::MutexGuard<'_, HashMap<Uuid, String>> {
        self.entries.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// How many times [`PasswordStore::store`] was invoked (including rejects).
    pub fn store_calls(&self) -> usize {
        self.store_calls.load(Ordering::SeqCst)
    }

    /// How many times [`PasswordStore::read`] was invoked.
    pub fn read_calls(&self) -> usize {
        self.read_calls.load(Ordering::SeqCst)
    }

    /// How many times [`PasswordStore::delete`] was invoked.
    pub fn delete_calls(&self) -> usize {
        self.delete_calls.load(Ordering::SeqCst)
    }

    /// How many stores were rejected by the size guard.
    pub fn reject_calls(&self) -> usize {
        self.reject_calls.load(Ordering::SeqCst)
    }

    /// Number of credentials currently held (tests).
    pub fn len(&self) -> usize {
        self.entries_guard().len()
    }

    /// Whether the memory store holds no credentials.
    pub fn is_empty(&self) -> bool {
        self.entries_guard().is_empty()
    }
}

impl PasswordStore for FakePasswordStore {
    fn store(&self, credential_id: &Uuid, password: &str) -> Result<()> {
        self.store_calls.fetch_add(1, Ordering::SeqCst);
        if let Err(err) = ensure_password_fits_cred_mgr(password) {
            self.reject_calls.fetch_add(1, Ordering::SeqCst);
            return Err(err);
        }
        self.entries_guard()
            .insert(*credential_id, password.to_owned());
        Ok(())
    }

    fn read(&self, credential_id: &Uuid) -> Result<Option<String>> {
        self.read_calls.fetch_add(1, Ordering::SeqCst);
        Ok(self.entries_guard().get(credential_id).cloned())
    }

    fn delete(&self, credential_id: &Uuid) -> Result<()> {
        self.delete_calls.fetch_add(1, Ordering::SeqCst);
        self.entries_guard().remove(credential_id);
        Ok(())
    }
}

/// Store a password under `Wormhole:<id>` with `CRED_PERSIST_LOCAL_MACHINE`.
///
/// Mirrors `CredentialManager.WriteCredential(..., persistence: LocalMachine)`.
/// Oversized secrets fail with [`SecretsError::PasswordTooLarge`] before
/// `CredWriteW`.
pub fn store_password(credential_id: &Uuid, password: &str) -> Result<()> {
    ensure_password_fits_cred_mgr(password)?;
    #[cfg(windows)]
    {
        store_password_windows(credential_id, password)
    }
    #[cfg(not(windows))]
    {
        let _ = (credential_id, password);
        Err(SecretsError::UnsupportedPlatform)
    }
}

/// Read a password; `Ok(None)` when the target is missing.
pub fn read_password(credential_id: &Uuid) -> Result<Option<String>> {
    #[cfg(windows)]
    {
        read_password_windows(credential_id)
    }
    #[cfg(not(windows))]
    {
        let _ = credential_id;
        Err(SecretsError::UnsupportedPlatform)
    }
}

/// Delete a credential. Missing targets succeed (matches C# best-effort delete).
pub fn delete_password(credential_id: &Uuid) -> Result<()> {
    #[cfg(windows)]
    {
        delete_password_windows(credential_id)
    }
    #[cfg(not(windows))]
    {
        let _ = credential_id;
        Err(SecretsError::UnsupportedPlatform)
    }
}

#[cfg(windows)]
fn store_password_windows(credential_id: &Uuid, password: &str) -> Result<()> {
    use windows::core::PWSTR;
    use windows::Win32::Security::Credentials::{
        CredWriteW, CREDENTIALW, CRED_FLAGS, CRED_PERSIST_LOCAL_MACHINE, CRED_TYPE_GENERIC,
    };

    // Caller already ran `ensure_password_fits_cred_mgr`. Blob size must match
    // the encoded UTF-16 buffer (not a second independent length source).
    let mut secret_w: Vec<u16> = password.encode_utf16().collect();
    let secret_bytes = secret_w.len() * 2;

    let target = credential_target(credential_id);
    let user_name = credential_id.to_string();
    let mut target_w = wide_null(&target);
    let mut user_w = wide_null(&user_name);
    let mut comment_w = wide_null(CREDENTIAL_COMMENT);

    // Empty secret: CredMgr accepts a zero-size blob; pass a non-null pointer only when non-empty.
    let blob_ptr = if secret_w.is_empty() {
        std::ptr::null_mut()
    } else {
        secret_w.as_mut_ptr() as *mut u8
    };

    let credential = CREDENTIALW {
        Flags: CRED_FLAGS(0),
        Type: CRED_TYPE_GENERIC,
        TargetName: PWSTR(target_w.as_mut_ptr()),
        Comment: PWSTR(comment_w.as_mut_ptr()),
        LastWritten: Default::default(),
        CredentialBlobSize: secret_bytes as u32,
        CredentialBlob: blob_ptr,
        Persist: CRED_PERSIST_LOCAL_MACHINE,
        AttributeCount: 0,
        Attributes: std::ptr::null_mut(),
        TargetAlias: PWSTR::null(),
        UserName: PWSTR(user_w.as_mut_ptr()),
    };

    let _keep = (&mut target_w, &mut user_w, &mut comment_w, &mut secret_w);

    unsafe {
        CredWriteW(&credential, 0).map_err(|e| crate::win32::win32_err("CredWriteW", e))?;
    }
    Ok(())
}

#[cfg(windows)]
fn read_password_windows(credential_id: &Uuid) -> Result<Option<String>> {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::ERROR_NOT_FOUND;
    use windows::Win32::Security::Credentials::{
        CredFree, CredReadW, CREDENTIALW, CRED_TYPE_GENERIC,
    };

    /// Frees a `CredReadW` buffer even if password decoding panics.
    struct CredGuard(*mut CREDENTIALW);

    impl Drop for CredGuard {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe { CredFree(self.0 as *const _) };
                self.0 = std::ptr::null_mut();
            }
        }
    }

    let target = credential_target(credential_id);
    let target_w = wide_null(&target);
    let mut pcred: *mut CREDENTIALW = std::ptr::null_mut();

    match unsafe {
        CredReadW(
            PCWSTR(target_w.as_ptr()),
            CRED_TYPE_GENERIC,
            None,
            &mut pcred,
        )
    } {
        Ok(()) => {}
        Err(e) => {
            if e.code() == ERROR_NOT_FOUND.to_hresult() {
                return Ok(None);
            }
            return Err(crate::win32::win32_err("CredReadW", e));
        }
    }

    let guard = CredGuard(pcred);
    let password = unsafe {
        let cred = &*guard.0;
        if cred.CredentialBlob.is_null() || cred.CredentialBlobSize == 0 {
            String::new()
        } else {
            let u16_len = (cred.CredentialBlobSize as usize) / 2;
            let slice = std::slice::from_raw_parts(cred.CredentialBlob as *const u16, u16_len);
            String::from_utf16_lossy(slice)
        }
    };
    Ok(Some(password))
}

#[cfg(windows)]
fn delete_password_windows(credential_id: &Uuid) -> Result<()> {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::ERROR_NOT_FOUND;
    use windows::Win32::Security::Credentials::{CredDeleteW, CRED_TYPE_GENERIC};

    let target = credential_target(credential_id);
    let target_w = wide_null(&target);
    match unsafe { CredDeleteW(PCWSTR(target_w.as_ptr()), CRED_TYPE_GENERIC, None) } {
        Ok(()) => Ok(()),
        Err(e) if e.code() == ERROR_NOT_FOUND.to_hresult() => Ok(()),
        Err(e) => Err(crate::win32::win32_err("CredDeleteW", e)),
    }
}

#[cfg(windows)]
fn wide_null(s: &str) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    std::ffi::OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utf16_byte_len_counts_code_units_not_utf8() {
        // U+00E9 is 2 UTF-8 bytes but 1 UTF-16 code unit.
        assert_eq!(password_utf16_byte_len("é"), 2);
        // U+1F512 (🔒) is 4 UTF-8 bytes and 1 surrogate pair (2 UTF-16 units).
        assert_eq!(password_utf16_byte_len("🔒"), 4);
        assert_eq!(password_utf16_byte_len(""), 0);
        assert_eq!(password_utf16_byte_len("ab"), 4);
        // Embedded NUL is one UTF-16 unit (CredMgr blob length, not C-string).
        assert_eq!(password_utf16_byte_len("a\0b"), 6);
        // chars()*2 under-counts surrogates; len()*2 over-counts BMP / UTF-8.
        assert_eq!("🔒".chars().count() * 2, 2);
        assert_eq!("🔒".len() * 2, 8);
        assert_eq!("é".len() * 2, 4);
    }

    #[test]
    fn near_limit_multibyte_ascii_mixed_is_accepted_by_size_check() {
        // 1280 × 'é' ⇒ 2560 UTF-16 bytes (at the CredMgr ceiling).
        let pw: String = std::iter::repeat_n('é', 1280).collect();
        assert_eq!(password_utf16_byte_len(&pw), MAX_PASSWORD_UTF16_BYTES);
        // Old `len()*2` would have been 5120 and falsely rejected.
        assert!(pw.len() * 2 > MAX_PASSWORD_UTF16_BYTES);
        ensure_password_fits_cred_mgr(&pw).expect("at-limit accepted");

        // 640 × 🔒 ⇒ 2560 UTF-16 bytes (surrogate pairs at the ceiling).
        let emoji: String = std::iter::repeat_n('🔒', 640).collect();
        assert_eq!(password_utf16_byte_len(&emoji), MAX_PASSWORD_UTF16_BYTES);
        // chars()*2 would under-count to 1280 and hide a later oversize bug.
        assert_eq!(emoji.chars().count() * 2, 1280);
        ensure_password_fits_cred_mgr(&emoji).expect("640 emoji at-limit accepted");

        // Mixed ASCII + surrogate exactly at the ceiling.
        let mixed = format!("{}🔒", "a".repeat(1278));
        assert_eq!(password_utf16_byte_len(&mixed), MAX_PASSWORD_UTF16_BYTES);
        ensure_password_fits_cred_mgr(&mixed).expect("mixed at-limit accepted");
    }

    #[test]
    fn ensure_rejects_oversize_without_echoing_secret() {
        let over: String = std::iter::repeat_n('a', 1281).collect();
        let err = ensure_password_fits_cred_mgr(&over).unwrap_err();
        match err {
            SecretsError::PasswordTooLarge { bytes: 2562 } => {}
            other => panic!("expected PasswordTooLarge(2562), got {other:?}"),
        }
        let display = err.to_string();
        let debug = format!("{err:?}");
        assert!(!display.contains(&over));
        assert!(!debug.contains(&over));
        assert!(!display.contains("aaa"));
        assert!(display.contains("2562"));
        assert!(display.contains("2560"));

        // 641 × 🔒 ⇒ 2564 UTF-16 bytes. chars()*2 == 1282 would falsely accept.
        let emoji_over: String = std::iter::repeat_n('🔒', 641).collect();
        assert_eq!(password_utf16_byte_len(&emoji_over), 2564);
        assert!(emoji_over.chars().count() * 2 < MAX_PASSWORD_UTF16_BYTES);
        let err = ensure_password_fits_cred_mgr(&emoji_over).unwrap_err();
        match err {
            SecretsError::PasswordTooLarge { bytes: 2564 } => {}
            other => panic!("expected PasswordTooLarge(2564), got {other:?}"),
        }
        assert!(!err.to_string().contains('🔒'));
        assert!(!format!("{err:?}").contains('🔒'));

        // Mixed oversize that chars()*2 mis-measures as exactly 2560.
        let mixed_over = format!("{}🔒", "a".repeat(1279));
        assert_eq!(password_utf16_byte_len(&mixed_over), 2562);
        assert_eq!(mixed_over.chars().count() * 2, MAX_PASSWORD_UTF16_BYTES);
        let err = ensure_password_fits_cred_mgr(&mixed_over).unwrap_err();
        match err {
            SecretsError::PasswordTooLarge { bytes: 2562 } => {}
            other => panic!("expected PasswordTooLarge(2562) mixed, got {other:?}"),
        }
    }

    #[test]
    fn fake_store_roundtrip_empty_and_unicode() {
        let store = FakePasswordStore::new();
        let id = Uuid::parse_str("f00dcafe-1000-4000-8000-0000deadbeef").unwrap();

        assert!(store.is_empty());
        store.store(&id, "").expect("empty");
        assert_eq!(store.read(&id).unwrap().as_deref(), Some(""));

        let unicode = "pässwörd-🔒-Σ";
        store.store(&id, unicode).expect("unicode");
        assert_eq!(store.read(&id).unwrap().as_deref(), Some(unicode));
        assert_eq!(store.len(), 1);

        store.delete(&id).unwrap();
        assert_eq!(store.read(&id).unwrap(), None);
        assert!(store.is_empty());
        assert_eq!(store.store_calls(), 2);
        assert_eq!(store.delete_calls(), 1);
    }

    #[test]
    fn fake_store_rejects_oversize_before_insert() {
        let store = FakePasswordStore::new();
        let id = Uuid::parse_str("f00dcafe-1001-4000-8000-0000deadbeef").unwrap();

        let at_limit: String = std::iter::repeat_n('a', 1280).collect();
        assert_eq!(password_utf16_byte_len(&at_limit), MAX_PASSWORD_UTF16_BYTES);
        store.store(&id, &at_limit).expect("1280 ASCII chars fit");
        assert_eq!(store.read(&id).unwrap().as_deref(), Some(at_limit.as_str()));

        let over: String = std::iter::repeat_n('a', 1281).collect();
        let err = store.store(&id, &over).unwrap_err();
        match err {
            SecretsError::PasswordTooLarge { bytes: 2562 } => {}
            other => panic!("expected PasswordTooLarge(2562), got {other:?}"),
        }
        // Prior at-limit value must remain — oversize never inserted.
        assert_eq!(store.read(&id).unwrap().as_deref(), Some(at_limit.as_str()));
        assert_eq!(store.reject_calls(), 1);
        assert!(!err.to_string().contains(&over));
        assert!(!format!("{err:?}").contains(&over));

        // Multibyte BMP at the UTF-16 ceiling must be accepted (not len()*2).
        let accents: String = std::iter::repeat_n('é', 1280).collect();
        assert_eq!(password_utf16_byte_len(&accents), MAX_PASSWORD_UTF16_BYTES);
        store.store(&id, &accents).expect("1280 × é fits UTF-16 limit");
        assert_eq!(store.read(&id).unwrap().as_deref(), Some(accents.as_str()));

        // Astral oversize must not replace the prior value (chars()*2 would accept).
        let emoji_over: String = std::iter::repeat_n('🔒', 641).collect();
        let err = store.store(&id, &emoji_over).unwrap_err();
        match err {
            SecretsError::PasswordTooLarge { bytes: 2564 } => {}
            other => panic!("expected PasswordTooLarge(2564), got {other:?}"),
        }
        assert_eq!(store.read(&id).unwrap().as_deref(), Some(accents.as_str()));
        assert_eq!(store.reject_calls(), 2);
        assert_eq!(store.len(), 1);
        assert!(!format!("{store:?}").contains('🔒'));
    }

    #[test]
    fn fake_store_debug_never_echoes_password() {
        let store = FakePasswordStore::new();
        let id = Uuid::parse_str("f00dcafe-1002-4000-8000-0000deadbeef").unwrap();
        let secret = "super-secret-password-value-do-not-log";
        store.store(&id, secret).unwrap();
        let debug = format!("{store:?}");
        assert!(!debug.contains(secret));
        assert!(!debug.contains("super-secret"));
        assert!(debug.contains("entry_count"));
        assert!(debug.contains("entry_utf16_byte_lengths"));
        // Lengths only — UTF-16 byte len of `secret`, never the string itself.
        assert!(debug.contains(&password_utf16_byte_len(secret).to_string()));
        assert!(debug.contains("reject_calls"));
    }

    #[test]
    fn fake_store_via_trait_object() {
        let store: Box<dyn PasswordStore> = Box::new(FakePasswordStore::new());
        let id = Uuid::new_v4();
        store.store(&id, "via-trait").unwrap();
        assert_eq!(store.read(&id).unwrap().as_deref(), Some("via-trait"));
        store.delete(&id).unwrap();
        assert_eq!(store.read(&id).unwrap(), None);
    }

    #[test]
    fn fake_store_missing_delete_is_ok() {
        let store = FakePasswordStore::new();
        let id = Uuid::new_v4();
        store.delete(&id).expect("missing delete succeeds");
        assert_eq!(store.delete_calls(), 1);
        // Second missing delete stays Ok (idempotent best-effort).
        store.delete(&id).expect("second missing delete succeeds");
        assert_eq!(store.delete_calls(), 2);
        assert_eq!(store.read(&id).unwrap(), None);
    }

    #[test]
    fn fake_store_multi_id_isolation_and_overwrite() {
        let store = FakePasswordStore::new();
        let a = Uuid::parse_str("f00dcafe-1003-4000-8000-0000deadbeef").unwrap();
        let b = Uuid::parse_str("f00dcafe-1004-4000-8000-0000deadbeef").unwrap();

        store.store(&a, "secret-a").unwrap();
        store.store(&b, "secret-b").unwrap();
        assert_eq!(store.read(&a).unwrap().as_deref(), Some("secret-a"));
        assert_eq!(store.read(&b).unwrap().as_deref(), Some("secret-b"));
        assert_eq!(store.len(), 2);

        store.store(&a, "secret-a-overwritten").unwrap();
        assert_eq!(store.read(&a).unwrap().as_deref(), Some("secret-a-overwritten"));
        // Sibling id untouched.
        assert_eq!(store.read(&b).unwrap().as_deref(), Some("secret-b"));

        store.delete(&a).unwrap();
        assert_eq!(store.read(&a).unwrap(), None);
        assert_eq!(store.read(&b).unwrap().as_deref(), Some("secret-b"));
        assert_eq!(store.len(), 1);

        let debug = format!("{store:?}");
        assert!(!debug.contains("secret-a"));
        assert!(!debug.contains("secret-b"));
        assert!(!debug.contains("overwritten"));
    }

    #[test]
    fn fake_store_concurrent_store_read_delete_no_panic() {
        use std::sync::{Arc, Barrier};

        let store = Arc::new(FakePasswordStore::new());
        let id_a = Uuid::parse_str("f00dcafe-1005-4000-8000-0000deadbeef").unwrap();
        let id_b = Uuid::parse_str("f00dcafe-1006-4000-8000-0000deadbeef").unwrap();
        store.store(&id_a, "seed-a").unwrap();
        store.store(&id_b, "seed-b").unwrap();

        let barrier = Arc::new(Barrier::new(12));
        let mut handles = Vec::new();
        for i in 0..12 {
            let s = Arc::clone(&store);
            let b = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                b.wait();
                let id = if i % 2 == 0 { id_a } else { id_b };
                match i % 4 {
                    0 => s.store(&id, &format!("pw-{i}")).expect("store"),
                    1 => {
                        let _ = s.read(&id).expect("read");
                    }
                    2 => s.delete(&id).expect("delete"),
                    _ => {
                        // Oversize must reject without poisoning the map / Debug.
                        let over: String = std::iter::repeat_n('x', 1281).collect();
                        let err = s.store(&id, &over).unwrap_err();
                        assert!(matches!(
                            err,
                            SecretsError::PasswordTooLarge { bytes: 2562 }
                        ));
                        assert!(!format!("{err:?}").contains('x'));
                    }
                }
                // Debug must never echo secrets even under concurrent mutation.
                let debug = format!("{s:?}");
                assert!(!debug.contains("seed-a"));
                assert!(!debug.contains("pw-"));
            }));
        }
        for h in handles {
            h.join().expect("thread");
        }
        // Store remains usable; Debug still length/count only.
        let _ = store.read(&id_a).unwrap();
        let _ = store.read(&id_b).unwrap();
        let debug = format!("{store:?}");
        assert!(debug.contains("entry_count"));
        assert!(!debug.contains("seed-a"));
        assert!(!debug.contains("seed-b"));
    }

    #[test]
    fn credential_target_uses_prefix_and_d_format_not_n() {
        let id = Uuid::nil();
        let target = credential_target(&id);
        assert!(target.starts_with(CREDENTIAL_PREFIX));
        assert_eq!(CREDENTIAL_PREFIX, "Wormhole:");
        assert_eq!(target, "Wormhole:00000000-0000-0000-0000-000000000000");
        // N-format (no hyphens) must never appear as the CredMgr target.
        assert!(!target.contains("00000000000000000000000000000000"));
        assert_eq!(target.matches('-').count(), 4);
        // Username field in WinCred writes uses the same D-format guid string.
        assert_eq!(id.to_string(), "00000000-0000-0000-0000-000000000000");
        assert_eq!(CREDENTIAL_COMMENT, "Wormhole credential");
    }
}
