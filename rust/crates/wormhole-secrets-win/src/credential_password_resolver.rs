//! Credential password resolution Fake glue (C# `CredentialPasswordResolver` password path).
//!
//! Resolves saved credential passwords from:
//! - **Local** — [`PasswordStore`] / [`FakePasswordStore`] (`Wormhole:<guid>`)
//! - **Bitwarden** — in-memory vault Fake keyed by item id (requires unlocked
//!   [`BitwardenSession`]; **no** live `bw` spawn)
//!
//! Compose with [`BitwardenCredentialCatalogGlue`] for virtual credential ids:
//! `catalog.get_by_id(id)?` then `resolver.read_password(&profile)`.
//!
//! Fail-closed: vault disabled, locked session, missing item ref, missing item,
//! empty / whitespace-only password, unsupported field path, non-password credential kind.
//! [`Debug`] and errors never carry password material — lengths only where noted.

use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use uuid::Uuid;
use wormhole_domain::{
    CredentialKind, CredentialSecretProvider, BITWARDEN_PASSWORD_FIELD_PATH,
};

use crate::bitwarden_credential_catalog::{
    BitwardenCatalogProfile, BitwardenCredentialCatalogGlue, BitwardenCredentialCacheSource,
    LocalCredentialCatalog,
};
use crate::bitwarden_session::{BitwardenSession, BitwardenSessionStatus};
use crate::cred_mgr::PasswordStore;

/// Errors from password resolution (never carry secrets).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CredentialPasswordError {
    /// Credential row is not a password credential (e.g. SSH key).
    #[error("credential is not a password credential")]
    NotPasswordCredential,
    /// No password stored for a local credential id.
    #[error("credential password not found")]
    NotFound,
    /// Stored / resolved password is empty or whitespace-only.
    #[error("credential password is empty")]
    EmptyPassword,
    /// Bitwarden vault toggle is off (C# `EnableBitwardenVault == false`).
    #[error("Bitwarden credential vault is disabled in Settings")]
    VaultDisabled,
    /// Bitwarden CLI session is locked (no memory-only session key).
    #[error("Bitwarden vault is locked")]
    VaultLocked,
    /// Bitwarden-linked profile missing `bitwarden_item_id`.
    #[error("Bitwarden item reference is missing")]
    MissingBitwardenItemId,
    /// Item id not present in the Fake vault catalog.
    #[error("linked Bitwarden login item was not found")]
    BitwardenItemNotFound,
    /// Item exists but `login.password` is absent / blank.
    #[error("linked Bitwarden item does not contain login.password")]
    BitwardenPasswordMissing,
    /// Only `login.password` is supported in v1.
    #[error("unsupported Bitwarden field path")]
    UnsupportedFieldPath,
    /// Local CredMgr read failed.
    #[error("local password read failed: {0}")]
    LocalRead(String),
}

/// Bitwarden login password source (Fake vault or future CLI adapter).
pub trait BitwardenVaultPasswordSource: Send + Sync {
    /// Read `login.password` for `item_id`. `Ok(None)` when the item is missing.
    fn read_login_password(
        &self,
        item_id: &str,
    ) -> Result<Option<String>, CredentialPasswordError>;
}

/// Password resolver (C# `ICredentialPasswordResolver` lab subset).
pub trait CredentialPasswordResolver: Send + Sync {
    /// Resolve password for a catalog / metadata profile.
    fn read_password(
        &self,
        profile: &BitwardenCatalogProfile,
    ) -> Result<String, CredentialPasswordError>;
}

/// Orchestrator — local [`PasswordStore`] + session + Fake vault passwords.
pub struct CredentialPasswordResolverGlue<P, S, V>
where
    P: PasswordStore,
    S: BitwardenSession,
    V: BitwardenVaultPasswordSource,
{
    local: P,
    session: S,
    vault: V,
    vault_enabled: bool,
    resolve_calls: AtomicUsize,
}

impl<P, S, V> fmt::Debug for CredentialPasswordResolverGlue<P, S, V>
where
    P: PasswordStore + Send + Sync,
    S: BitwardenSession,
    V: BitwardenVaultPasswordSource,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CredentialPasswordResolverGlue")
            .field("vault_enabled", &self.vault_enabled)
            .field("session_status", &self.session.status())
            .field("resolve_calls", &self.resolve_calls.load(Ordering::SeqCst))
            .finish()
    }
}

impl<P, S, V> CredentialPasswordResolverGlue<P, S, V>
where
    P: PasswordStore + Send + Sync,
    S: BitwardenSession,
    V: BitwardenVaultPasswordSource,
{
    /// Construct resolver with injectable local store, session, vault Fake, and settings flag.
    pub fn new(local: P, session: S, vault: V, vault_enabled: bool) -> Self {
        Self {
            local,
            session,
            vault,
            vault_enabled,
            resolve_calls: AtomicUsize::new(0),
        }
    }

    /// How many times [`CredentialPasswordResolver::read_password`] ran.
    pub fn resolve_calls(&self) -> usize {
        self.resolve_calls.load(Ordering::SeqCst)
    }

    /// Resolve by credential id via catalog glue (local + virtual rows).
    pub fn read_password_by_id<L, C, CatS>(
        &self,
        catalog: &BitwardenCredentialCatalogGlue<L, C, CatS>,
        credential_id: Uuid,
    ) -> Result<String, CredentialPasswordError>
    where
        L: LocalCredentialCatalog,
        C: BitwardenCredentialCacheSource,
        CatS: BitwardenSession,
    {
        let profile = catalog
            .get_by_id(credential_id)
            .map_err(|e| CredentialPasswordError::LocalRead(e.to_string()))?
            .ok_or(CredentialPasswordError::NotFound)?;
        self.read_password(&profile)
    }

    fn resolve_local(&self, credential_id: &Uuid) -> Result<String, CredentialPasswordError> {
        let password = self
            .local
            .read(credential_id)
            .map_err(|e| CredentialPasswordError::LocalRead(e.to_string()))?
            .ok_or(CredentialPasswordError::NotFound)?;
        ensure_non_empty_password(&password)
    }

    fn resolve_bitwarden(&self, profile: &BitwardenCatalogProfile) -> Result<String, CredentialPasswordError> {
        if !self.vault_enabled {
            return Err(CredentialPasswordError::VaultDisabled);
        }
        if self.session.status() != BitwardenSessionStatus::Unlocked {
            return Err(CredentialPasswordError::VaultLocked);
        }
        let _ = self.session.session_key(); // parity check — must not log

        let item_id = profile
            .bitwarden_item_id
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or(CredentialPasswordError::MissingBitwardenItemId)?;

        let field_path = profile
            .bitwarden_field_path
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or(BITWARDEN_PASSWORD_FIELD_PATH);
        if field_path != BITWARDEN_PASSWORD_FIELD_PATH {
            return Err(CredentialPasswordError::UnsupportedFieldPath);
        }

        let password = self
            .vault
            .read_login_password(item_id)?
            .ok_or(CredentialPasswordError::BitwardenItemNotFound)?;
        ensure_non_empty_password(&password)
    }
}

impl<P, S, V> CredentialPasswordResolver for CredentialPasswordResolverGlue<P, S, V>
where
    P: PasswordStore + Send + Sync,
    S: BitwardenSession,
    V: BitwardenVaultPasswordSource,
{
    fn read_password(
        &self,
        profile: &BitwardenCatalogProfile,
    ) -> Result<String, CredentialPasswordError> {
        self.resolve_calls.fetch_add(1, Ordering::SeqCst);
        if profile.kind != CredentialKind::Password {
            return Err(CredentialPasswordError::NotPasswordCredential);
        }
        match profile.secret_provider {
            CredentialSecretProvider::Local => self.resolve_local(&profile.id),
            CredentialSecretProvider::Bitwarden => self.resolve_bitwarden(profile),
        }
    }
}

/// UTF-8 byte length safe to log after a successful resolve (never the string).
#[inline]
pub fn resolved_password_len(password: &str) -> usize {
    password.len()
}

fn ensure_non_empty_password(password: &str) -> Result<String, CredentialPasswordError> {
    if password.trim().is_empty() {
        return Err(CredentialPasswordError::EmptyPassword);
    }
    Ok(password.to_owned())
}

#[derive(Default)]
struct FakeVaultInner {
    passwords: HashMap<String, String>,
}

/// In-memory Bitwarden login.password store (tests / lab; no `bw` JSON).
#[derive(Default)]
pub struct FakeBitwardenVaultPasswords {
    inner: Mutex<FakeVaultInner>,
    read_calls: AtomicUsize,
}

impl FakeBitwardenVaultPasswords {
    /// Empty vault.
    pub fn new() -> Self {
        Self::default()
    }

    /// Seed item-id → password mappings (lab only — use opaque tokens in tests).
    pub fn with_items(items: impl IntoIterator<Item = (impl Into<String>, impl Into<String>)>) -> Self {
        let mut passwords = HashMap::new();
        for (id, pw) in items {
            passwords.insert(id.into(), pw.into());
        }
        Self {
            inner: Mutex::new(FakeVaultInner { passwords }),
            read_calls: AtomicUsize::new(0),
        }
    }

    /// Passwords aligned with [`crate::demo_bitwarden_cache_entries`] item ids.
    pub fn with_demo_passwords() -> Self {
        Self::with_items([
            ("lab-router", "demo-router-secret"),
            ("lab-server", "demo-server-secret"),
            ("lab-switch", "demo-switch-secret"),
        ])
    }

    /// Replace or insert a single item password.
    pub fn insert(&self, item_id: impl Into<String>, password: impl Into<String>) {
        self.inner
            .lock()
            .expect("mutex")
            .passwords
            .insert(item_id.into(), password.into());
    }

    /// How many vault reads were attempted.
    pub fn read_calls(&self) -> usize {
        self.read_calls.load(Ordering::SeqCst)
    }
}

impl fmt::Debug for FakeBitwardenVaultPasswords {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let guard = self.inner.lock().expect("mutex");
        let lengths: Vec<usize> = guard.passwords.values().map(|p| p.len()).collect();
        f.debug_struct("FakeBitwardenVaultPasswords")
            .field("item_count", &guard.passwords.len())
            .field("password_utf8_lengths", &lengths)
            .field("read_calls", &self.read_calls.load(Ordering::SeqCst))
            .finish()
    }
}

impl BitwardenVaultPasswordSource for FakeBitwardenVaultPasswords {
    fn read_login_password(
        &self,
        item_id: &str,
    ) -> Result<Option<String>, CredentialPasswordError> {
        self.read_calls.fetch_add(1, Ordering::SeqCst);
        let guard = self.inner.lock().expect("mutex");
        let trimmed = item_id.trim();
        Ok(guard.passwords.get(trimmed).cloned())
    }
}

impl BitwardenVaultPasswordSource for &FakeBitwardenVaultPasswords {
    fn read_login_password(
        &self,
        item_id: &str,
    ) -> Result<Option<String>, CredentialPasswordError> {
        (*self).read_login_password(item_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        bitwarden_virtual_credential_ids::BitwardenCredentialCacheEntry,
        FakeBitwardenCredentialCache, FakeBitwardenSession, FakeLocalCredentialCatalog,
        FakePasswordStore, SecretsError, StubBitwardenSession,
    };
    use wormhole_domain::ProtocolType;

    type TestResolver = CredentialPasswordResolverGlue<
        FakePasswordStore,
        FakeBitwardenSession,
        FakeBitwardenVaultPasswords,
    >;

    fn unlocked_session() -> FakeBitwardenSession {
        let session = FakeBitwardenSession::with_session_key("opaque-lab-session");
        assert!(session.unlock("lab-master").unlocked);
        session
    }

    fn enabled_resolver(
        local: FakePasswordStore,
        session: FakeBitwardenSession,
        vault: FakeBitwardenVaultPasswords,
    ) -> TestResolver {
        CredentialPasswordResolverGlue::new(local, session, vault, true)
    }

    fn local_profile(id: Uuid, name: &str) -> BitwardenCatalogProfile {
        BitwardenCatalogProfile::local_password(id, name, ProtocolType::Ssh, Some("user".into()))
    }

    #[test]
    fn local_password_roundtrip_via_fake_credmgr() {
        let id = Uuid::new_v4();
        let local = FakePasswordStore::new();
        local.store(&id, "local-secret").unwrap();
        let resolver = enabled_resolver(local, unlocked_session(), FakeBitwardenVaultPasswords::new());
        let pw = resolver
            .read_password(&local_profile(id, "lab"))
            .expect("resolve");
        assert_eq!(pw, "local-secret");
        assert_eq!(resolved_password_len(&pw), pw.len());
        assert_eq!(resolver.resolve_calls(), 1);
    }

    #[test]
    fn local_missing_and_empty_fail_closed() {
        let id = Uuid::new_v4();

        let missing = enabled_resolver(
            FakePasswordStore::new(),
            unlocked_session(),
            FakeBitwardenVaultPasswords::new(),
        );
        assert_eq!(
            missing.read_password(&local_profile(id, "x")),
            Err(CredentialPasswordError::NotFound)
        );

        let whitespace_local = FakePasswordStore::new();
        whitespace_local.store(&id, "   ").unwrap();
        let whitespace = enabled_resolver(
            whitespace_local,
            unlocked_session(),
            FakeBitwardenVaultPasswords::new(),
        );
        assert_eq!(
            whitespace.read_password(&local_profile(id, "x")),
            Err(CredentialPasswordError::EmptyPassword)
        );

        let empty_local = FakePasswordStore::new();
        empty_local.store(&id, "").unwrap();
        let empty = enabled_resolver(
            empty_local,
            unlocked_session(),
            FakeBitwardenVaultPasswords::new(),
        );
        assert_eq!(
            empty.read_password(&local_profile(id, "x")),
            Err(CredentialPasswordError::EmptyPassword)
        );
    }

    #[test]
    fn bitwarden_unlocked_resolves_demo_item() {
        let profile = BitwardenCatalogProfile::linked_bitwarden(
            Uuid::new_v4(),
            "Router",
            ProtocolType::Ssh,
            "lab-router",
            Some("admin".into()),
        );
        let resolver = enabled_resolver(
            FakePasswordStore::new(),
            unlocked_session(),
            FakeBitwardenVaultPasswords::with_demo_passwords(),
        );
        let pw = resolver.read_password(&profile).expect("bw pw");
        assert_eq!(pw, "demo-router-secret");
    }

    #[test]
    fn bitwarden_locked_vault_disabled_and_missing_item_fail_closed() {
        let profile = BitwardenCatalogProfile::linked_bitwarden(
            Uuid::new_v4(),
            "Router",
            ProtocolType::Ssh,
            "lab-router",
            None,
        );
        let locked = CredentialPasswordResolverGlue::new(
            FakePasswordStore::new(),
            StubBitwardenSession,
            FakeBitwardenVaultPasswords::with_demo_passwords(),
            true,
        );
        assert_eq!(
            locked.read_password(&profile),
            Err(CredentialPasswordError::VaultLocked)
        );

        let disabled = CredentialPasswordResolverGlue::new(
            FakePasswordStore::new(),
            unlocked_session(),
            FakeBitwardenVaultPasswords::with_demo_passwords(),
            false,
        );
        assert_eq!(
            disabled.read_password(&profile),
            Err(CredentialPasswordError::VaultDisabled)
        );

        let unlocked = enabled_resolver(
            FakePasswordStore::new(),
            unlocked_session(),
            FakeBitwardenVaultPasswords::with_demo_passwords(),
        );
        let mut missing_item = profile.clone();
        missing_item.bitwarden_item_id = Some("   ".into());
        assert_eq!(
            unlocked.read_password(&missing_item),
            Err(CredentialPasswordError::MissingBitwardenItemId)
        );

        let mut unknown = profile;
        unknown.bitwarden_item_id = Some("no-such-item".into());
        assert_eq!(
            unlocked.read_password(&unknown),
            Err(CredentialPasswordError::BitwardenItemNotFound)
        );
    }

    #[test]
    fn bitwarden_empty_vault_password_fail_closed() {
        let profile = BitwardenCatalogProfile::linked_bitwarden(
            Uuid::new_v4(),
            "Blank",
            ProtocolType::Ssh,
            "blank-item",
            None,
        );
        let vault = FakeBitwardenVaultPasswords::with_items([("blank-item", "  ")]);
        let resolver = enabled_resolver(FakePasswordStore::new(), unlocked_session(), vault);
        assert_eq!(
            resolver.read_password(&profile),
            Err(CredentialPasswordError::EmptyPassword)
        );
        let vault2 = FakeBitwardenVaultPasswords::with_items([("blank-item", "")]);
        let resolver2 = enabled_resolver(FakePasswordStore::new(), unlocked_session(), vault2);
        assert_eq!(
            resolver2.read_password(&profile),
            Err(CredentialPasswordError::EmptyPassword)
        );
    }

    #[test]
    fn virtual_credential_id_resolves_via_catalog_compose() {
        let entry = BitwardenCredentialCacheEntry::new("server", "Server", Some("root".into()));
        let virtual_id = entry.ssh_credential_id;
        let catalog = BitwardenCredentialCatalogGlue::new(
            FakeLocalCredentialCatalog::new(),
            FakeBitwardenCredentialCache::with_entries([entry]),
            unlocked_session(),
            true,
        );
        let resolver = CredentialPasswordResolverGlue::new(
            FakePasswordStore::new(),
            unlocked_session(),
            FakeBitwardenVaultPasswords::with_items([("server", "virtual-server-pw")]),
            true,
        );
        let pw = resolver
            .read_password_by_id(&catalog, virtual_id)
            .expect("virtual");
        assert_eq!(pw, "virtual-server-pw");
    }

    #[test]
    fn locked_catalog_virtual_id_fails_before_vault_read() {
        let entry = BitwardenCredentialCacheEntry::new("server", "Server", Some("root".into()));
        let virtual_id = entry.ssh_credential_id;
        let catalog = BitwardenCredentialCatalogGlue::new(
            FakeLocalCredentialCatalog::new(),
            FakeBitwardenCredentialCache::with_entries([entry]),
            StubBitwardenSession,
            true,
        );
        let vault = FakeBitwardenVaultPasswords::with_demo_passwords();
        let resolver = CredentialPasswordResolverGlue::new(
            FakePasswordStore::new(),
            StubBitwardenSession,
            vault,
            true,
        );
        assert_eq!(
            resolver.read_password_by_id(&catalog, virtual_id),
            Err(CredentialPasswordError::NotFound)
        );
        assert_eq!(resolver.resolve_calls(), 0);
    }

    #[test]
    fn unsupported_field_path_and_ssh_key_kind_fail_closed() {
        let mut profile = BitwardenCatalogProfile::linked_bitwarden(
            Uuid::new_v4(),
            "R",
            ProtocolType::Ssh,
            "lab-router",
            None,
        );
        profile.bitwarden_field_path = Some("login.custom".into());
        let resolver = enabled_resolver(
            FakePasswordStore::new(),
            unlocked_session(),
            FakeBitwardenVaultPasswords::with_demo_passwords(),
        );
        assert_eq!(
            resolver.read_password(&profile),
            Err(CredentialPasswordError::UnsupportedFieldPath)
        );

        let mut key_profile = local_profile(Uuid::new_v4(), "key");
        key_profile.kind = CredentialKind::SshKey;
        assert_eq!(
            resolver.read_password(&key_profile),
            Err(CredentialPasswordError::NotPasswordCredential)
        );
    }

    #[test]
    fn debug_and_errors_never_echo_secrets() {
        let secret = "super-secret-password-never-log";
        let id = Uuid::new_v4();
        let local = FakePasswordStore::new();
        local.store(&id, secret).unwrap();
        let vault = FakeBitwardenVaultPasswords::with_items([("item", secret)]);
        let vault_dbg = format!("{vault:?}");
        let resolver = enabled_resolver(local, unlocked_session(), vault);
        let dbg = format!("{resolver:?}");
        assert!(!dbg.contains(secret));
        assert!(!dbg.contains("super-secret"));
        assert!(dbg.contains("Unlocked"));

        assert!(!vault_dbg.contains(secret));
        assert!(vault_dbg.contains("password_utf8_lengths"));

        let err = resolver
            .read_password(&BitwardenCatalogProfile::linked_bitwarden(
                Uuid::new_v4(),
                "x",
                ProtocolType::Ssh,
                "missing",
                None,
            ))
            .unwrap_err();
        let err_s = err.to_string();
        let err_dbg = format!("{err:?}");
        assert!(!err_s.contains(secret));
        assert!(!err_dbg.contains(secret));
    }

    #[test]
    fn local_read_io_error_maps_without_password_echo() {
        #[derive(Default)]
        struct FailingStore;
        impl PasswordStore for FailingStore {
            fn store(&self, _id: &Uuid, _password: &str) -> Result<(), SecretsError> {
                Ok(())
            }
            fn read(&self, _id: &Uuid) -> Result<Option<String>, SecretsError> {
                Err(SecretsError::UnsupportedPlatform)
            }
            fn delete(&self, _id: &Uuid) -> Result<(), SecretsError> {
                Ok(())
            }
        }
        let resolver = CredentialPasswordResolverGlue::new(
            FailingStore,
            unlocked_session(),
            FakeBitwardenVaultPasswords::new(),
            false,
        );
        let err = resolver
            .read_password(&local_profile(Uuid::new_v4(), "x"))
            .unwrap_err();
        assert!(matches!(err, CredentialPasswordError::LocalRead(_)));
        assert!(!format!("{err}").contains("hunter2"));
    }
}
