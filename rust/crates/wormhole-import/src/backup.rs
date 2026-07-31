//! Wormhole backup document envelope (metadata only — no secret crypto yet).
//!
//! Mirrors `Models/Backup/BackupDocument.cs` camelCase JSON shape for Inspect /
//! schema gating. Payload row types stay deferred; this spike covers the
//! envelope + encryption discriminator.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::ImportError;
use crate::limits::{read_file_capped, MAX_IMPORT_FILE_BYTES};

/// Matches C# `BackupDocument.CurrentSchemaVersion`.
pub const CURRENT_SCHEMA_VERSION: i32 = 2;

/// Encryption discriminator values (C# `BackupEncryption`).
pub mod encryption {
    pub const NONE: &str = "none";
    pub const AES_GCM: &str = "aes-gcm";
}

/// Top-level backup file envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BackupDocument {
    pub schema_version: i32,
    pub app: String,
    pub exported_at: String,
    pub encryption: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<BackupPayload>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encrypted_payload: Option<BackupEncryptedPayload>,
}

impl BackupDocument {
    pub fn plaintext_empty(exported_at: impl Into<String>) -> Self {
        Self {
            schema_version: CURRENT_SCHEMA_VERSION,
            app: "Wormhole".into(),
            exported_at: exported_at.into(),
            encryption: encryption::NONE.into(),
            payload: Some(BackupPayload::default()),
            encrypted_payload: None,
        }
    }

    pub fn is_encrypted(&self) -> bool {
        self.encryption.eq_ignore_ascii_case(encryption::AES_GCM)
    }
}

/// Sealed blob fields when `encryption == "aes-gcm"`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BackupEncryptedPayload {
    pub kdf: String,
    pub iterations: i32,
    pub salt_b64: String,
    pub nonce_b64: String,
    pub ciphertext_b64: String,
    pub tag_b64: String,
}

/// Inline plaintext payload (counts only for this spike — full row types later).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BackupPayload {
    #[serde(default)]
    pub nodes: Vec<serde_json::Value>,
    #[serde(default)]
    pub credentials: Vec<serde_json::Value>,
    #[serde(default)]
    pub tunnels: Vec<serde_json::Value>,
    #[serde(default)]
    pub bitwarden_credential_cache: Vec<serde_json::Value>,
    #[serde(default)]
    pub passwords: Vec<serde_json::Value>,
    #[serde(default)]
    pub inline_passwords: Vec<serde_json::Value>,
    #[serde(default)]
    pub private_keys: Vec<serde_json::Value>,
    #[serde(default)]
    pub tunnel_payloads: Vec<serde_json::Value>,
}

/// Inspect result without decrypting (mirrors `BackupInspectResult`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupInspectResult {
    pub encrypted: bool,
    pub schema_version: i32,
    pub exported_at: String,
}

/// Parse a backup JSON document and return inspect metadata.
///
/// Uses a slim envelope so credential/tunnel payload arrays are not materialized.
pub fn inspect_backup_json(json: &str) -> Result<BackupInspectResult, ImportError> {
    if json.len() as u64 > MAX_IMPORT_FILE_BYTES {
        return Err(ImportError::InvalidData(format!(
            "backup JSON is {} bytes; refusing anything larger than {MAX_IMPORT_FILE_BYTES} bytes",
            json.len()
        )));
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct InspectEnvelope {
        schema_version: i32,
        exported_at: String,
        encryption: String,
    }
    let env: InspectEnvelope = serde_json::from_str(json)?;
    if env.schema_version <= 0 {
        return Err(ImportError::InvalidData(format!(
            "invalid backup schemaVersion {}",
            env.schema_version
        )));
    }
    validate_encryption(&env.encryption)?;
    Ok(BackupInspectResult {
        encrypted: env.encryption.eq_ignore_ascii_case(encryption::AES_GCM),
        schema_version: env.schema_version,
        exported_at: env.exported_at,
    })
}

/// Inspect a backup file on disk (size-capped; rejects `..` / NUL path components).
pub fn inspect_backup_path(path: impl AsRef<Path>) -> Result<BackupInspectResult, ImportError> {
    let bytes = read_file_capped(path.as_ref())?;
    let json = std::str::from_utf8(&bytes)
        .map_err(|_| ImportError::InvalidData("backup file is not valid UTF-8".into()))?;
    inspect_backup_json(json)
}

fn validate_encryption(encryption: &str) -> Result<(), ImportError> {
    if encryption.eq_ignore_ascii_case(encryption::NONE)
        || encryption.eq_ignore_ascii_case(encryption::AES_GCM)
    {
        return Ok(());
    }
    if encryption.trim().is_empty() {
        return Err(ImportError::InvalidData(
            "Backup file is missing its encryption marker.".into(),
        ));
    }
    Err(ImportError::InvalidData(format!(
        "Backup file uses unsupported encryption '{encryption}'."
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inspect_plaintext_envelope() {
        let doc = BackupDocument::plaintext_empty("2026-07-31T12:00:00Z");
        let json = serde_json::to_string_pretty(&doc).unwrap();
        assert!(json.contains("\"encryption\": \"none\""));
        assert!(!json.contains("\"password\":"), "must not embed credential secrets");
        let info = inspect_backup_json(&json).unwrap();
        assert!(!info.encrypted);
        assert_eq!(info.schema_version, CURRENT_SCHEMA_VERSION);
        assert_eq!(info.exported_at, "2026-07-31T12:00:00Z");
    }

    #[test]
    fn inspect_encrypted_envelope_without_secrets() {
        let doc = BackupDocument {
            schema_version: CURRENT_SCHEMA_VERSION,
            app: "Wormhole".into(),
            exported_at: "2026-07-31T12:00:00Z".into(),
            encryption: encryption::AES_GCM.into(),
            payload: None,
            encrypted_payload: Some(BackupEncryptedPayload {
                kdf: "pbkdf2-sha256".into(),
                iterations: 600_000,
                salt_b64: "AAAAAAAAAAAAAAAAAAAAAA==".into(),
                nonce_b64: "AAAAAAAAAAAA".into(),
                ciphertext_b64: "AQID".into(),
                tag_b64: "AAAAAAAAAAAAAAAAAAAAAA==".into(),
            }),
        };
        let json = serde_json::to_string(&doc).unwrap();
        let info = inspect_backup_json(&json).unwrap();
        assert!(info.encrypted);
        assert_eq!(info.schema_version, 2);
    }

    #[test]
    fn inspect_rejects_unsupported_encryption() {
        let json = r#"{"schemaVersion":2,"app":"Wormhole","exportedAt":"t","encryption":"xor"}"#;
        let err = inspect_backup_json(json).unwrap_err();
        assert!(err.to_string().contains("unsupported encryption"), "{err}");
    }

    #[test]
    fn inspect_path_rejects_parent_dir() {
        let err = inspect_backup_path(Path::new("..\\evil.json")).unwrap_err();
        assert!(
            err.to_string().contains("..") || err.to_string().contains("path"),
            "{err}"
        );
    }

    #[test]
    fn inspect_rejects_empty_encryption_marker() {
        let json = r#"{"schemaVersion":2,"app":"Wormhole","exportedAt":"t","encryption":""}"#;
        let err = inspect_backup_json(json).unwrap_err();
        assert!(err.to_string().contains("encryption"), "{err}");
    }
}
