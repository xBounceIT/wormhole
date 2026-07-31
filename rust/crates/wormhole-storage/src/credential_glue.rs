//! Thin create / rename / delete glue over [`CredentialRepository`].
//!
//! Metadata rows only — password bodies stay in CredMgr (or a
//! [`MemoryCredentialSecrets`] / `FakePasswordStore` stub). Never logs secrets.

use std::fmt;
use std::sync::Mutex;

use uuid::Uuid;
use wormhole_domain::{
    CredentialKind, CredentialSecretProvider, ProtocolType, BITWARDEN_PASSWORD_FIELD_PATH,
};

use crate::models::CredentialProfile;
use crate::repos::CredentialRepository;
use crate::Result;

/// Draft fields for [`create_credential_profile`] (no password body).
#[derive(Debug, Clone)]
pub struct CredentialProfileDraft {
    pub id: Uuid,
    pub name: String,
    pub username: Option<String>,
    pub domain: Option<String>,
    pub kind: CredentialKind,
    pub private_key_file_name: Option<String>,
    pub protocol: ProtocolType,
    pub secret_provider: CredentialSecretProvider,
    pub bitwarden_item_id: Option<String>,
    pub bitwarden_item_name: Option<String>,
    pub bitwarden_field_path: Option<String>,
}

impl CredentialProfileDraft {
    /// Local password credential defaults (C# `CredentialProfile` construction).
    pub fn local_password(id: Uuid, name: impl Into<String>) -> Self {
        Self {
            id,
            name: name.into(),
            username: None,
            domain: None,
            kind: CredentialKind::Password,
            private_key_file_name: None,
            protocol: ProtocolType::Ssh,
            secret_provider: CredentialSecretProvider::Local,
            bitwarden_item_id: None,
            bitwarden_item_name: None,
            bitwarden_field_path: Some(BITWARDEN_PASSWORD_FIELD_PATH.to_owned()),
        }
    }
}

/// Out-of-band CredMgr / DPAPI cleanup keyed by credential profile id.
///
/// Production wires `wormhole-secrets-win::{PasswordStore, KeyMaterialStore}`;
/// unit tests inject [`MemoryCredentialSecrets`] (or adapt `FakePasswordStore`).
/// Implementations must **never** log password / key material.
pub trait CredentialSecrets: Send + Sync {
    /// Best-effort CredMgr delete (`Wormhole:<guid:D>`). Missing targets succeed.
    fn delete_password(&self, credential_id: &Uuid) -> std::result::Result<(), String>;

    /// Best-effort private-key DPAPI delete under `keys\`. Missing targets succeed.
    fn delete_private_key(&self, credential_id: &Uuid) -> std::result::Result<(), String>;
}

/// In-memory CredMgr / key cleanup stub for unit tests (holds **no** secret bodies).
///
/// Tracks deleted ids only — `Debug` never echoes passwords.
#[derive(Default)]
pub struct MemoryCredentialSecrets {
    deleted_passwords: Mutex<Vec<Uuid>>,
    deleted_keys: Mutex<Vec<Uuid>>,
}

impl MemoryCredentialSecrets {
    pub fn new() -> Self {
        Self::default()
    }

    /// Credential ids whose passwords were deleted (tests).
    pub fn deleted_password_ids(&self) -> Vec<Uuid> {
        self.deleted_passwords
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Credential ids whose private keys were deleted (tests).
    pub fn deleted_key_ids(&self) -> Vec<Uuid> {
        self.deleted_keys
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
}

impl fmt::Debug for MemoryCredentialSecrets {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MemoryCredentialSecrets")
            .field("cred_mgr_delete_count", &self.deleted_password_ids().len())
            .field("key_delete_count", &self.deleted_key_ids().len())
            .finish()
    }
}

impl CredentialSecrets for MemoryCredentialSecrets {
    fn delete_password(&self, credential_id: &Uuid) -> std::result::Result<(), String> {
        self.deleted_passwords
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(*credential_id);
        Ok(())
    }

    fn delete_private_key(&self, credential_id: &Uuid) -> std::result::Result<(), String> {
        self.deleted_keys
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(*credential_id);
        Ok(())
    }
}

/// Create a credential profile metadata row (fail-closed on blank name).
///
/// Does **not** accept or store a password — callers that need CredMgr write
/// through `wormhole-secrets-win::PasswordStore` / `FakePasswordStore` separately.
pub fn create_credential_profile(
    repo: &CredentialRepository<'_>,
    draft: CredentialProfileDraft,
) -> Result<CredentialProfile> {
    let profile = CredentialProfile {
        id: draft.id,
        name: draft.name,
        username: draft.username,
        domain: draft.domain,
        kind: draft.kind,
        private_key_file_name: draft.private_key_file_name,
        protocol: draft.protocol,
        secret_provider: draft.secret_provider,
        bitwarden_item_id: draft.bitwarden_item_id,
        bitwarden_item_name: draft.bitwarden_item_name,
        bitwarden_field_path: draft.bitwarden_field_path,
        // Placeholder — `insert` stamps CreatedAt.
        created_at: chrono::DateTime::UNIX_EPOCH,
    };
    repo.insert(profile)
}

/// Rename a credential profile (trim + fail-closed blank name). Other metadata unchanged.
pub fn rename_credential_profile(
    repo: &CredentialRepository<'_>,
    id: Uuid,
    new_name: &str,
) -> Result<CredentialProfile> {
    let mut profile = repo.get_by_id(id)?.ok_or(crate::StorageError::NotFound(id))?;
    profile.name = new_name.to_owned();
    repo.update(&profile)?;
    // Re-read so callers see the exact DB row (trimmed name + field-path normalization).
    repo.get_by_id(id)?
        .ok_or(crate::StorageError::NotFound(id))
}

/// Delete metadata, then best-effort out-of-band CredMgr / key cleanup.
///
/// Ordering matches C# `CredentialsViewModel.DeleteCredentialAsync`: SQLite row
/// first (source of truth), then secret cleanup. Secret cleanup errors are
/// ignored at this layer (C# best-effort CredMgr delete) — metadata is already gone.
pub fn delete_credential_profile(
    repo: &CredentialRepository<'_>,
    id: Uuid,
    secrets: Option<&dyn CredentialSecrets>,
) -> Result<()> {
    repo.delete(id)?;
    if let Some(secrets) = secrets {
        let _ = secrets.delete_password(&id);
        let _ = secrets.delete_private_key(&id);
    }
    Ok(())
}
