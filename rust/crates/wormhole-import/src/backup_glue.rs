//! LabOnly backup export/import Fake glue (metadata + secret round-trip).
//!
//! Mirrors C# `BackupService` merge-skip semantics at the metadata + Fake
//! CredMgr / DPAPI layer. Uses temp / in-memory stores only — never zips real
//! user AppData. **Never** logs password / key / tunnel payload bodies.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::path::Path;
use std::sync::Mutex;

use base64::Engine;
use chrono::Utc;
use uuid::Uuid;
use wormhole_domain::{ConnectionNode, CredentialKind, CredentialSecretProvider, NodeKind};
use wormhole_secrets_win::{
    FakeKeyMaterialStore, FakePasswordStore, FakeTunnelPayloadStore, KeyMaterialStore,
    PasswordStore, TunnelPayloadStore,
};
use wormhole_storage::{
    ConnectionRepository, CredentialRepository, CredentialProfile, TunnelConfig,
    TunnelConfigRepository,
};

use crate::backup::{encryption, inspect_backup_json, BackupDocument, CURRENT_SCHEMA_VERSION};
use crate::backup_crypto::{seal_payload, unseal_payload};
use crate::backup_payload::{
    BackupConnectionNode, BackupCredentialProfile, BackupInlinePasswordEntry, BackupPasswordEntry,
    BackupPayloadRows, BackupPrivateKeyEntry, BackupTunnelConfig, BackupTunnelPayloadEntry,
};
use crate::error::ImportError;
use crate::limits::{read_file_capped, validate_user_path};

/// Outcome of [`export_backup`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupExportResult {
    pub path: String,
    pub node_count: usize,
    pub credential_count: usize,
    pub tunnel_count: usize,
    pub password_count: usize,
    pub private_key_count: usize,
    pub tunnel_payload_count: usize,
    pub encrypted: bool,
}

/// Outcome of [`import_backup`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BackupImportResult {
    pub nodes_imported: usize,
    pub nodes_skipped: usize,
    pub credentials_imported: usize,
    pub credentials_skipped: usize,
    pub tunnels_imported: usize,
    pub tunnels_skipped: usize,
    pub passwords_imported: usize,
    pub private_keys_imported: usize,
    pub tunnel_payloads_imported: usize,
    pub warnings: Vec<String>,
}

/// Metadata source for backup export (Fake or SQLite-backed).
pub trait BackupMetadataSource {
    fn list_nodes(&self) -> Result<Vec<ConnectionNode>, ImportError>;
    fn list_credentials(&self) -> Result<Vec<CredentialProfile>, ImportError>;
    fn list_tunnels(&self) -> Result<Vec<TunnelConfig>, ImportError>;
    fn list_bitwarden_cache(&self) -> Result<Vec<serde_json::Value>, ImportError>;
}

/// Metadata sink for backup import (Fake or SQLite-backed).
pub trait BackupMetadataSink {
    fn existing_credential_ids(&self) -> Result<HashSet<Uuid>, ImportError>;
    fn existing_credential_names(&self) -> Result<HashSet<String>, ImportError>;
    fn existing_tunnel_ids(&self) -> Result<HashSet<Uuid>, ImportError>;
    fn existing_tunnel_names(&self) -> Result<HashSet<String>, ImportError>;
    fn existing_node_ids(&self) -> Result<HashSet<Uuid>, ImportError>;

    fn insert_credential(&self, profile: CredentialProfile) -> Result<(), ImportError>;
    fn insert_tunnel(&self, config: TunnelConfig) -> Result<(), ImportError>;
    fn insert_node(&self, node: ConnectionNode) -> Result<(), ImportError>;
}

/// Secret read/write port for backup (Fake CredMgr + DPAPI stores).
pub trait BackupSecretsPort: Send + Sync {
    fn read_password(&self, id: &Uuid) -> Result<Option<String>, ImportError>;
    fn store_password(&self, id: &Uuid, password: &str) -> Result<(), ImportError>;
    fn has_password(&self, id: &Uuid) -> Result<bool, ImportError>;

    fn read_private_key(&self, id: &Uuid) -> Result<Option<Vec<u8>>, ImportError>;
    fn store_private_key(&self, id: &Uuid, bytes: &[u8]) -> Result<(), ImportError>;
    fn has_private_key(&self, id: &Uuid) -> Result<bool, ImportError>;

    fn read_tunnel_payload(&self, id: &Uuid) -> Result<Option<Vec<u8>>, ImportError>;
    fn store_tunnel_payload(&self, id: &Uuid, bytes: &[u8]) -> Result<(), ImportError>;
    fn has_tunnel_payload(&self, id: &Uuid) -> Result<bool, ImportError>;
}

/// In-memory lab store: metadata vectors + composed Fake secret stores.
pub struct FakeBackupLab {
    nodes: Mutex<Vec<ConnectionNode>>,
    credentials: Mutex<Vec<CredentialProfile>>,
    tunnels: Mutex<Vec<TunnelConfig>>,
    bitwarden_cache: Mutex<Vec<serde_json::Value>>,
    passwords: FakePasswordStore,
    keys: FakeKeyMaterialStore,
    tunnel_payloads: FakeTunnelPayloadStore,
    /// Inline passwords keyed by **node** id (CredMgr parity).
    inline_passwords: Mutex<HashMap<Uuid, String>>,
}

impl Default for FakeBackupLab {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for FakeBackupLab {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FakeBackupLab")
            .field("node_count", &self.nodes.lock().map(|n| n.len()).unwrap_or(0))
            .field(
                "credential_count",
                &self.credentials.lock().map(|c| c.len()).unwrap_or(0),
            )
            .field("tunnel_count", &self.tunnels.lock().map(|t| t.len()).unwrap_or(0))
            .field("passwords", &self.passwords)
            .field("keys", &self.keys)
            .field("tunnel_payloads", &self.tunnel_payloads)
            .field(
                "inline_password_count",
                &self.inline_passwords.lock().map(|m| m.len()).unwrap_or(0),
            )
            .finish()
    }
}

impl FakeBackupLab {
    pub fn new() -> Self {
        Self {
            nodes: Mutex::new(Vec::new()),
            credentials: Mutex::new(Vec::new()),
            tunnels: Mutex::new(Vec::new()),
            bitwarden_cache: Mutex::new(Vec::new()),
            passwords: FakePasswordStore::new(),
            keys: FakeKeyMaterialStore::new(),
            tunnel_payloads: FakeTunnelPayloadStore::new(),
            inline_passwords: Mutex::new(HashMap::new()),
        }
    }

    pub fn seed_node(&self, node: ConnectionNode) {
        self.nodes
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(node);
    }

    pub fn seed_credential(&self, profile: CredentialProfile) {
        self.credentials
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(profile);
    }

    pub fn seed_tunnel(&self, config: TunnelConfig) {
        self.tunnels
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(config);
    }

    pub fn store_credential_password(
        &self,
        id: &Uuid,
        password: &str,
    ) -> Result<(), ImportError> {
        self.passwords
            .store(id, password)
            .map_err(map_secrets_err)
    }

    pub fn store_inline_password(&self, node_id: &Uuid, password: impl Into<String>) {
        self.inline_passwords
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(*node_id, password.into());
    }

    pub fn read_credential_password(&self, id: &Uuid) -> Result<Option<String>, ImportError> {
        self.passwords.read(id).map_err(map_secrets_err)
    }

    pub fn read_inline_password(&self, node_id: &Uuid) -> Option<String> {
        self.inline_passwords
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(node_id)
            .cloned()
    }
}

impl BackupMetadataSource for FakeBackupLab {
    fn list_nodes(&self) -> Result<Vec<ConnectionNode>, ImportError> {
        Ok(self
            .nodes
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone())
    }

    fn list_credentials(&self) -> Result<Vec<CredentialProfile>, ImportError> {
        Ok(self
            .credentials
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone())
    }

    fn list_tunnels(&self) -> Result<Vec<TunnelConfig>, ImportError> {
        Ok(self
            .tunnels
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone())
    }

    fn list_bitwarden_cache(&self) -> Result<Vec<serde_json::Value>, ImportError> {
        Ok(self
            .bitwarden_cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone())
    }
}

impl BackupMetadataSink for FakeBackupLab {
    fn existing_credential_ids(&self) -> Result<HashSet<Uuid>, ImportError> {
        Ok(self
            .credentials
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .map(|c| c.id)
            .collect())
    }

    fn existing_credential_names(&self) -> Result<HashSet<String>, ImportError> {
        Ok(self
            .credentials
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .map(|c| c.name.clone())
            .collect())
    }

    fn existing_tunnel_ids(&self) -> Result<HashSet<Uuid>, ImportError> {
        Ok(self
            .tunnels
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .map(|t| t.id)
            .collect())
    }

    fn existing_tunnel_names(&self) -> Result<HashSet<String>, ImportError> {
        Ok(self
            .tunnels
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .map(|t| t.name.clone())
            .collect())
    }

    fn existing_node_ids(&self) -> Result<HashSet<Uuid>, ImportError> {
        Ok(self
            .nodes
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .map(|n| n.id)
            .collect())
    }

    fn insert_credential(&self, profile: CredentialProfile) -> Result<(), ImportError> {
        self.credentials
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(profile);
        Ok(())
    }

    fn insert_tunnel(&self, config: TunnelConfig) -> Result<(), ImportError> {
        self.tunnels
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(config);
        Ok(())
    }

    fn insert_node(&self, node: ConnectionNode) -> Result<(), ImportError> {
        self.nodes
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(node);
        Ok(())
    }
}

impl BackupSecretsPort for FakeBackupLab {
    fn read_password(&self, id: &Uuid) -> Result<Option<String>, ImportError> {
        if let Some(inline) = self.read_inline_password(id) {
            return Ok(Some(inline));
        }
        self.passwords.read(id).map_err(map_secrets_err)
    }

    fn store_password(&self, id: &Uuid, password: &str) -> Result<(), ImportError> {
        self.passwords.store(id, password).map_err(map_secrets_err)
    }

    fn has_password(&self, id: &Uuid) -> Result<bool, ImportError> {
        Ok(self.read_password(id)?.is_some())
    }

    fn read_private_key(&self, id: &Uuid) -> Result<Option<Vec<u8>>, ImportError> {
        self.keys.read(id).map_err(map_secrets_err)
    }

    fn store_private_key(&self, id: &Uuid, bytes: &[u8]) -> Result<(), ImportError> {
        self.keys.store(id, bytes).map_err(map_secrets_err)
    }

    fn has_private_key(&self, id: &Uuid) -> Result<bool, ImportError> {
        Ok(self.read_private_key(id)?.is_some())
    }

    fn read_tunnel_payload(&self, id: &Uuid) -> Result<Option<Vec<u8>>, ImportError> {
        self.tunnel_payloads.read(id).map_err(map_secrets_err)
    }

    fn store_tunnel_payload(&self, id: &Uuid, bytes: &[u8]) -> Result<(), ImportError> {
        self.tunnel_payloads
            .store(id, bytes)
            .map_err(map_secrets_err)
    }

    fn has_tunnel_payload(&self, id: &Uuid) -> Result<bool, ImportError> {
        Ok(self.read_tunnel_payload(id)?.is_some())
    }
}

/// SQLite-backed metadata source for export.
pub struct StorageBackupSource<'a> {
    pub connections: ConnectionRepository<'a>,
    pub credentials: CredentialRepository<'a>,
    pub tunnels: TunnelConfigRepository<'a>,
}

impl BackupMetadataSource for StorageBackupSource<'_> {
    fn list_nodes(&self) -> Result<Vec<ConnectionNode>, ImportError> {
        Ok(self
            .connections
            .list_all()?
            .into_iter()
            .map(|s| s.node)
            .collect())
    }

    fn list_credentials(&self) -> Result<Vec<CredentialProfile>, ImportError> {
        self.credentials.list_all().map_err(ImportError::from)
    }

    fn list_tunnels(&self) -> Result<Vec<TunnelConfig>, ImportError> {
        self.tunnels.list_all().map_err(ImportError::from)
    }

    fn list_bitwarden_cache(&self) -> Result<Vec<serde_json::Value>, ImportError> {
        // No Rust repository yet — export empty (refs-only spike).
        Ok(Vec::new())
    }
}

/// SQLite-backed metadata sink for import.
pub struct StorageBackupSink<'a> {
    pub connections: ConnectionRepository<'a>,
    pub credentials: CredentialRepository<'a>,
    pub tunnels: TunnelConfigRepository<'a>,
}

impl BackupMetadataSink for StorageBackupSink<'_> {
    fn existing_credential_ids(&self) -> Result<HashSet<Uuid>, ImportError> {
        Ok(self
            .credentials
            .list_all()?
            .into_iter()
            .map(|c| c.id)
            .collect())
    }

    fn existing_credential_names(&self) -> Result<HashSet<String>, ImportError> {
        Ok(self
            .credentials
            .list_all()?
            .into_iter()
            .map(|c| c.name)
            .collect())
    }

    fn existing_tunnel_ids(&self) -> Result<HashSet<Uuid>, ImportError> {
        Ok(self
            .tunnels
            .list_all()?
            .into_iter()
            .map(|t| t.id)
            .collect())
    }

    fn existing_tunnel_names(&self) -> Result<HashSet<String>, ImportError> {
        Ok(self
            .tunnels
            .list_all()?
            .into_iter()
            .map(|t| t.name)
            .collect())
    }

    fn existing_node_ids(&self) -> Result<HashSet<Uuid>, ImportError> {
        Ok(self
            .connections
            .list_all()?
            .into_iter()
            .map(|n| n.node.id)
            .collect())
    }

    fn insert_credential(&self, profile: CredentialProfile) -> Result<(), ImportError> {
        self.credentials.insert(profile)?;
        Ok(())
    }

    fn insert_tunnel(&self, config: TunnelConfig) -> Result<(), ImportError> {
        self.tunnels
            .insert(config.id, &config.name, config.kind)?;
        Ok(())
    }

    fn insert_node(&self, node: ConnectionNode) -> Result<(), ImportError> {
        self.connections.insert(&node)?;
        Ok(())
    }
}

/// Build a backup payload from metadata + secrets (no file I/O).
pub fn build_backup_payload(
    source: &dyn BackupMetadataSource,
    secrets: &dyn BackupSecretsPort,
) -> Result<BackupPayloadRows, ImportError> {
    let nodes = source.list_nodes()?;
    let credentials = source.list_credentials()?;
    let tunnels = source.list_tunnels()?;
    let bitwarden_credential_cache = source.list_bitwarden_cache()?;

    let mut payload = BackupPayloadRows {
        nodes: nodes.iter().map(BackupConnectionNode::from).collect(),
        credentials: credentials.iter().map(BackupCredentialProfile::from).collect(),
        tunnels: tunnels.iter().map(BackupTunnelConfig::from).collect(),
        bitwarden_credential_cache,
        ..Default::default()
    };

    for cred in &credentials {
        if cred.secret_provider == CredentialSecretProvider::Bitwarden {
            continue;
        }
        if cred.kind == CredentialKind::Password {
            if let Some(pwd) = secrets.read_password(&cred.id)? {
                if !pwd.is_empty() {
                    payload.passwords.push(BackupPasswordEntry {
                        credential_id: cred.id,
                        password: pwd,
                    });
                }
            }
        } else if cred.kind == CredentialKind::SshKey {
            if let Some(bytes) = secrets.read_private_key(&cred.id)? {
                payload.private_keys.push(BackupPrivateKeyEntry {
                    credential_id: cred.id,
                    original_file_name: cred.private_key_file_name.clone(),
                    data_b64: base64::engine::general_purpose::STANDARD.encode(bytes),
                });
            }
        }
    }

    for node in &nodes {
        if node.kind == NodeKind::Connection && node.use_inline_password == Some(true) {
            if let Some(pwd) = secrets.read_password(&node.id)? {
                if !pwd.is_empty() {
                    payload.inline_passwords.push(BackupInlinePasswordEntry {
                        node_id: node.id,
                        password: pwd,
                    });
                }
            }
        }
    }

    for tunnel in &tunnels {
        if let Some(bytes) = secrets.read_tunnel_payload(&tunnel.id)? {
            payload.tunnel_payloads.push(BackupTunnelPayloadEntry {
                tunnel_config_id: tunnel.id,
                data_b64: base64::engine::general_purpose::STANDARD.encode(bytes),
            });
        }
    }

    Ok(payload)
}

/// Serialize + write a backup file (atomic temp → rename).
pub fn export_backup(
    target_path: impl AsRef<Path>,
    source: &dyn BackupMetadataSource,
    secrets: &dyn BackupSecretsPort,
    password: Option<&str>,
) -> Result<BackupExportResult, ImportError> {
    let target_path = target_path.as_ref();
    validate_user_path(target_path)?;

    let payload = build_backup_payload(source, secrets)?;
    let encrypt = password.is_some_and(|p| !p.is_empty());

    let doc = if encrypt {
        let pw = password.unwrap();
        let payload_json = serde_json::to_vec(&payload)?;
        let sealed = seal_payload(&payload_json, pw);
        BackupDocument {
            schema_version: CURRENT_SCHEMA_VERSION,
            app: "Wormhole".into(),
            exported_at: Utc::now().to_rfc3339(),
            encryption: encryption::AES_GCM.into(),
            payload: None,
            encrypted_payload: Some(sealed),
        }
    } else {
        BackupDocument {
            schema_version: CURRENT_SCHEMA_VERSION,
            app: "Wormhole".into(),
            exported_at: Utc::now().to_rfc3339(),
            encryption: encryption::NONE.into(),
            payload: Some(backup_payload_to_legacy(payload.clone())),
            encrypted_payload: None,
        }
    };

    let temp_path = target_path.with_extension("tmp");
    let json = serde_json::to_vec_pretty(&doc)?;
    std::fs::write(&temp_path, &json)?;
    std::fs::rename(&temp_path, target_path).map_err(|e| {
        let _ = std::fs::remove_file(&temp_path);
        ImportError::Io(e)
    })?;

    Ok(BackupExportResult {
        path: target_path.display().to_string(),
        node_count: payload.nodes.len(),
        credential_count: payload.credentials.len(),
        tunnel_count: payload.tunnels.len(),
        password_count: payload.passwords.len() + payload.inline_passwords.len(),
        private_key_count: payload.private_keys.len(),
        tunnel_payload_count: payload.tunnel_payloads.len(),
        encrypted: encrypt,
    })
}

/// Parse backup bytes into payload rows (decrypt when needed).
pub fn parse_backup_payload(
    json: &str,
    password: Option<&str>,
) -> Result<BackupPayloadRows, ImportError> {
    if json.trim().is_empty() {
        return Err(ImportError::InvalidData(
            "backup file is empty or malformed".into(),
        ));
    }
    inspect_backup_json(json)?;

    let doc: BackupDocument = serde_json::from_str(json)?;
    if doc.schema_version > CURRENT_SCHEMA_VERSION {
        return Err(ImportError::InvalidData(format!(
            "backup schema version {} is newer than supported {}",
            doc.schema_version, CURRENT_SCHEMA_VERSION
        )));
    }

    if doc.is_encrypted() {
        let pw = password.filter(|p| !p.is_empty()).ok_or_else(|| {
            ImportError::InvalidData("encrypted backup requires a password".into())
        })?;
        let sealed = doc
            .encrypted_payload
            .as_ref()
            .ok_or_else(|| ImportError::InvalidData("encrypted backup is missing sealed payload".into()))?;
        let plain = unseal_payload(sealed, pw).map_err(|_| {
            ImportError::InvalidData("backup decrypt failed (wrong password or tampered file)".into())
        })?;
        serde_json::from_slice(&plain).map_err(ImportError::from)
    } else {
        let legacy = doc
            .payload
            .ok_or_else(|| ImportError::InvalidData("backup is missing its payload".into()))?;
        Ok(legacy_payload_to_rows(legacy)?)
    }
}

/// Read + import a backup file into a metadata sink + secrets port.
pub fn import_backup(
    source_path: impl AsRef<Path>,
    sink: &dyn BackupMetadataSink,
    secrets: &dyn BackupSecretsPort,
    password: Option<&str>,
) -> Result<BackupImportResult, ImportError> {
    let bytes = read_file_capped(source_path.as_ref())?;
    let json = std::str::from_utf8(&bytes)
        .map_err(|_| ImportError::InvalidData("backup file is not valid UTF-8".into()))?;
    let payload = parse_backup_payload(json, password)?;
    import_backup_payload(&payload, sink, secrets)
}

/// Apply parsed payload (merge-skip metadata + conditional secret restore).
pub fn import_backup_payload(
    payload: &BackupPayloadRows,
    sink: &dyn BackupMetadataSink,
    secrets: &dyn BackupSecretsPort,
) -> Result<BackupImportResult, ImportError> {
    let mut result = BackupImportResult::default();

    let mut existing_cred_ids = sink.existing_credential_ids()?;
    let mut existing_cred_names = sink.existing_credential_names()?;
    let mut credential_providers: HashMap<Uuid, CredentialSecretProvider> = HashMap::new();

    let mut inserted_cred_ids = HashSet::new();
    for row in &payload.credentials {
        let mut profile: CredentialProfile = row.clone().try_into()?;
        profile.name = profile.name.trim().to_string();
        if profile.name.is_empty() {
            profile.name = String::new();
        }
        if existing_cred_ids.contains(&profile.id) {
            result.credentials_skipped += 1;
            credential_providers.insert(profile.id, profile.secret_provider);
            continue;
        }
        if existing_cred_names.contains(&profile.name) {
            result.credentials_skipped += 1;
            result.warnings.push(format!(
                "Credential '{}' already exists with a different ID and was skipped.",
                profile.name
            ));
            continue;
        }
        credential_providers.insert(profile.id, profile.secret_provider);
        sink.insert_credential(profile.clone())?;
        existing_cred_ids.insert(profile.id);
        existing_cred_names.insert(profile.name.clone());
        inserted_cred_ids.insert(profile.id);
        result.credentials_imported += 1;
    }

    let mut existing_tunnel_ids = sink.existing_tunnel_ids()?;
    let mut existing_tunnel_names = sink.existing_tunnel_names()?;
    let mut inserted_tunnel_ids = HashSet::new();
    for row in &payload.tunnels {
        let config: TunnelConfig = row.clone().try_into()?;
        let name = config.name.trim().to_string();
        if existing_tunnel_ids.contains(&config.id) {
            result.tunnels_skipped += 1;
            continue;
        }
        if existing_tunnel_names.contains(&name) {
            result.tunnels_skipped += 1;
            result.warnings.push(format!(
                "Tunnel '{name}' already exists with a different ID and was skipped."
            ));
            continue;
        }
        sink.insert_tunnel(config.clone())?;
        existing_tunnel_ids.insert(config.id);
        existing_tunnel_names.insert(name);
        inserted_tunnel_ids.insert(config.id);
        result.tunnels_imported += 1;
    }

    let mut existing_node_ids = sink.existing_node_ids()?;
    let ordered = topologically_order_nodes(&payload.nodes, &existing_node_ids, &mut result)?;
    let mut inserted_node_ids = HashSet::new();
    for row in ordered {
        let node: ConnectionNode = row.try_into()?;
        if existing_node_ids.contains(&node.id) {
            result.nodes_skipped += 1;
            continue;
        }
        sink.insert_node(node.clone())?;
        existing_node_ids.insert(node.id);
        inserted_node_ids.insert(node.id);
        result.nodes_imported += 1;
    }

    for entry in &payload.passwords {
        if credential_providers
            .get(&entry.credential_id)
            .copied()
            .is_some_and(|p| p == CredentialSecretProvider::Bitwarden)
        {
            continue;
        }
        if !should_restore_secret(
            &entry.credential_id,
            &inserted_cred_ids,
            &existing_cred_ids,
            || secrets.has_password(&entry.credential_id),
        )? {
            continue;
        }
        secrets.store_password(&entry.credential_id, &entry.password)?;
        result.passwords_imported += 1;
    }

    for entry in &payload.inline_passwords {
        if !should_restore_secret(
            &entry.node_id,
            &inserted_node_ids,
            &existing_node_ids,
            || secrets.has_password(&entry.node_id),
        )? {
            continue;
        }
        secrets.store_password(&entry.node_id, &entry.password)?;
        result.passwords_imported += 1;
    }

    for entry in &payload.private_keys {
        if !should_restore_secret(
            &entry.credential_id,
            &inserted_cred_ids,
            &existing_cred_ids,
            || secrets.has_private_key(&entry.credential_id),
        )? {
            continue;
        }
        let bytes = decode_b64_or_warn(&entry.data_b64, &mut result, "Private key")?;
        if let Some(bytes) = bytes {
            secrets.store_private_key(&entry.credential_id, &bytes)?;
            result.private_keys_imported += 1;
        }
    }

    for entry in &payload.tunnel_payloads {
        if !should_restore_secret(
            &entry.tunnel_config_id,
            &inserted_tunnel_ids,
            &existing_tunnel_ids,
            || secrets.has_tunnel_payload(&entry.tunnel_config_id),
        )? {
            continue;
        }
        let bytes = decode_b64_or_warn(&entry.data_b64, &mut result, "Tunnel payload")?;
        if let Some(bytes) = bytes {
            secrets.store_tunnel_payload(&entry.tunnel_config_id, &bytes)?;
            result.tunnel_payloads_imported += 1;
        }
    }

    Ok(result)
}

fn should_restore_secret(
    id: &Uuid,
    inserted: &HashSet<Uuid>,
    existing: &HashSet<Uuid>,
    has_secret: impl FnOnce() -> Result<bool, ImportError>,
) -> Result<bool, ImportError> {
    if inserted.contains(id) {
        return Ok(true);
    }
    if existing.contains(id) && !has_secret()? {
        return Ok(true);
    }
    Ok(false)
}

fn decode_b64_or_warn(
    data_b64: &str,
    result: &mut BackupImportResult,
    label: &str,
) -> Result<Option<Vec<u8>>, ImportError> {
    match base64::engine::general_purpose::STANDARD.decode(data_b64.trim()) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(_) => {
            result
                .warnings
                .push(format!("{label} entry was malformed and was skipped."));
            Ok(None)
        }
    }
}

fn topologically_order_nodes(
    nodes: &[BackupConnectionNode],
    existing_ids: &HashSet<Uuid>,
    result: &mut BackupImportResult,
) -> Result<Vec<BackupConnectionNode>, ImportError> {
    let mut by_id: HashMap<Uuid, BackupConnectionNode> = HashMap::new();
    for row in nodes {
        let id = row.id;
        if by_id.contains_key(&id) {
            result.warnings.push(format!(
                "Duplicate node id {id} in backup; only the first occurrence was imported."
            ));
            continue;
        }
        by_id.insert(id, row.clone());
    }
    let ids_in_backup: HashSet<Uuid> = by_id.keys().copied().collect();

    let mut ordered_ids = HashSet::new();
    let mut ordered = Vec::with_capacity(by_id.len());
    let mut pending: Vec<BackupConnectionNode> = by_id.into_values().collect();

    while !pending.is_empty() {
        let before = pending.len();
        let mut next_pending = Vec::new();
        for mut node in pending {
            let parent_ready = match node.parent_id {
                None => true,
                Some(pid) if existing_ids.contains(&pid) => true,
                Some(pid) if ordered_ids.contains(&pid) => true,
                Some(pid) if !ids_in_backup.contains(&pid) => {
                    result.warnings.push(format!(
                        "Node '{}' references unknown parent {pid}; will be imported at root.",
                        node.name
                    ));
                    node.parent_id = None;
                    true
                }
                _ => false,
            };
            if parent_ready {
                ordered_ids.insert(node.id);
                ordered.push(node);
            } else {
                next_pending.push(node);
            }
        }
        if next_pending.len() == before {
            for mut node in next_pending {
                result.warnings.push(format!(
                    "Node '{}' could not resolve parent; imported at root.",
                    node.name
                ));
                node.parent_id = None;
                ordered_ids.insert(node.id);
                ordered.push(node);
            }
            break;
        }
        pending = next_pending;
    }
    Ok(ordered)
}

fn map_secrets_err(err: wormhole_secrets_win::SecretsError) -> ImportError {
    ImportError::InvalidData(err.to_string())
}

/// Bridge legacy [`crate::backup::BackupPayload`] (`serde_json::Value` arrays) to typed rows.
fn legacy_payload_to_rows(legacy: crate::backup::BackupPayload) -> Result<BackupPayloadRows, ImportError> {
    fn decode_vec<T: serde::de::DeserializeOwned>(
        values: Vec<serde_json::Value>,
        field: &str,
    ) -> Result<Vec<T>, ImportError> {
        values
            .into_iter()
            .map(|v| {
                serde_json::from_value(v).map_err(|e| {
                    ImportError::InvalidData(format!("backup payload field '{field}' is malformed: {e}"))
                })
            })
            .collect()
    }
    Ok(BackupPayloadRows {
        nodes: decode_vec(legacy.nodes, "nodes")?,
        credentials: decode_vec(legacy.credentials, "credentials")?,
        tunnels: decode_vec(legacy.tunnels, "tunnels")?,
        bitwarden_credential_cache: legacy.bitwarden_credential_cache,
        passwords: decode_vec(legacy.passwords, "passwords")?,
        inline_passwords: decode_vec(legacy.inline_passwords, "inlinePasswords")?,
        private_keys: decode_vec(legacy.private_keys, "privateKeys")?,
        tunnel_payloads: decode_vec(legacy.tunnel_payloads, "tunnelPayloads")?,
    })
}

fn backup_payload_to_legacy(rows: BackupPayloadRows) -> crate::backup::BackupPayload {
    crate::backup::BackupPayload {
        nodes: serde_json::to_value(rows.nodes)
            .ok()
            .and_then(|v| v.as_array().cloned())
            .unwrap_or_default(),
        credentials: serde_json::to_value(rows.credentials)
            .ok()
            .and_then(|v| v.as_array().cloned())
            .unwrap_or_default(),
        tunnels: serde_json::to_value(rows.tunnels)
            .ok()
            .and_then(|v| v.as_array().cloned())
            .unwrap_or_default(),
        bitwarden_credential_cache: rows.bitwarden_credential_cache,
        passwords: serde_json::to_value(rows.passwords)
            .ok()
            .and_then(|v| v.as_array().cloned())
            .unwrap_or_default(),
        inline_passwords: serde_json::to_value(rows.inline_passwords)
            .ok()
            .and_then(|v| v.as_array().cloned())
            .unwrap_or_default(),
        private_keys: serde_json::to_value(rows.private_keys)
            .ok()
            .and_then(|v| v.as_array().cloned())
            .unwrap_or_default(),
        tunnel_payloads: serde_json::to_value(rows.tunnel_payloads)
            .ok()
            .and_then(|v| v.as_array().cloned())
            .unwrap_or_default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{inspect_backup_json, CURRENT_SCHEMA_VERSION};
    use chrono::Utc;
    use tempfile::TempDir;
    use wormhole_domain::{CredentialKind, ProtocolType, TunnelKind};
    use wormhole_storage::{MigrationRunner, SqliteConnectionFactory};

    fn sample_lab() -> (FakeBackupLab, Uuid, Uuid, Uuid, Uuid) {
        let lab = FakeBackupLab::new();
        let folder_id = Uuid::new_v4();
        let leaf_id = Uuid::new_v4();
        let cred_id = Uuid::new_v4();
        let ssh_cred_id = Uuid::new_v4();
        let tunnel_id = Uuid::new_v4();

        lab.seed_node(ConnectionNode {
            id: folder_id,
            name: "Servers".into(),
            kind: NodeKind::Folder,
            ..Default::default()
        });
        lab.seed_node(ConnectionNode {
            id: leaf_id,
            parent_id: Some(folder_id),
            name: "prod".into(),
            kind: NodeKind::Connection,
            protocol: Some(ProtocolType::Ssh),
            host: Some("server.example.com".into()),
            credential_id: Some(cred_id),
            ..Default::default()
        });

        lab.seed_credential(CredentialProfile {
            id: cred_id,
            name: "admin".into(),
            username: None,
            domain: None,
            kind: CredentialKind::Password,
            private_key_file_name: None,
            protocol: ProtocolType::Ssh,
            secret_provider: CredentialSecretProvider::Local,
            bitwarden_item_id: None,
            bitwarden_item_name: None,
            bitwarden_field_path: None,
            created_at: Utc::now(),
        });

        lab.seed_credential(CredentialProfile {
            id: ssh_cred_id,
            name: "ssh-key".into(),
            kind: CredentialKind::SshKey,
            private_key_file_name: Some("id_rsa".into()),
            protocol: ProtocolType::Ssh,
            secret_provider: CredentialSecretProvider::Local,
            created_at: Utc::now(),
            username: None,
            domain: None,
            bitwarden_item_id: None,
            bitwarden_item_name: None,
            bitwarden_field_path: None,
        });

        lab.seed_tunnel(TunnelConfig {
            id: tunnel_id,
            name: "corp-vpn".into(),
            kind: TunnelKind::WireGuard,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        });

        lab.store_credential_password(&cred_id, "hunter2").unwrap();
        lab.keys.store(&ssh_cred_id, &[1, 2, 3, 4, 5]).unwrap();
        lab.tunnel_payloads
            .store(&tunnel_id, &[9, 8, 7])
            .unwrap();

        (lab, folder_id, leaf_id, cred_id, tunnel_id)
    }

    #[test]
    fn fake_plain_roundtrip() {
        let (src, _folder, leaf_id, cred_id, tunnel_id) = sample_lab();
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("plain.json");

        let export = export_backup(&path, &src, &src, None).unwrap();
        assert!(!export.encrypted);
        assert_eq!(export.node_count, 2);
        assert_eq!(export.password_count, 1);
        assert_eq!(export.private_key_count, 1);
        assert_eq!(export.tunnel_payload_count, 1);

        let dst = FakeBackupLab::new();
        let import = import_backup(&path, &dst, &dst, None).unwrap();
        assert_eq!(import.nodes_imported, 2);
        assert_eq!(import.credentials_imported, 2);
        assert_eq!(import.tunnels_imported, 1);
        assert_eq!(import.passwords_imported, 1);
        assert_eq!(import.private_keys_imported, 1);
        assert_eq!(import.tunnel_payloads_imported, 1);

        assert_eq!(
            dst.read_credential_password(&cred_id).unwrap().as_deref(),
            Some("hunter2")
        );
        assert_eq!(dst.keys.read(&cred_id).unwrap(), None);
        let ssh_id = dst
            .credentials
            .lock()
            .unwrap()
            .iter()
            .find(|c| c.kind == CredentialKind::SshKey)
            .map(|c| c.id)
            .unwrap();
        assert_eq!(dst.keys.read(&ssh_id).unwrap().as_deref(), Some(&[1, 2, 3, 4, 5][..]));
        assert_eq!(
            dst.tunnel_payloads.read(&tunnel_id).unwrap().as_deref(),
            Some(&[9, 8, 7][..])
        );
        let nodes = dst.nodes.lock().unwrap();
        let leaf = nodes.iter().find(|n| n.id == leaf_id).unwrap();
        assert_eq!(leaf.host.as_deref(), Some("server.example.com"));
    }

    #[test]
    fn encrypted_roundtrip() {
        let (src, ..) = sample_lab();
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("enc.json");
        export_backup(&path, &src, &src, Some("backup-pw")).unwrap();
        let dst = FakeBackupLab::new();
        import_backup(&path, &dst, &dst, Some("backup-pw")).unwrap();
        let cred_id = src.credentials.lock().unwrap()[0].id;
        assert_eq!(
            dst.read_credential_password(&cred_id).unwrap().as_deref(),
            Some("hunter2")
        );
    }

    #[test]
    fn wrong_password_fails_closed() {
        let (src, ..) = sample_lab();
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("enc.json");
        export_backup(&path, &src, &src, Some("right")).unwrap();
        let dst = FakeBackupLab::new();
        let err = import_backup(&path, &dst, &dst, Some("wrong")).unwrap_err();
        assert!(err.to_string().contains("decrypt"), "{err}");
    }

    #[test]
    fn truncated_file_fails_closed() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("trunc.json");
        std::fs::write(&path, br#"{"schemaVersion":2,"app":"Worm"#).unwrap();
        let dst = FakeBackupLab::new();
        assert!(import_backup(&path, &dst, &dst, None).is_err());
    }

    #[test]
    fn bitwarden_password_not_exported() {
        let lab = FakeBackupLab::new();
        let cred_id = Uuid::new_v4();
        lab.seed_credential(CredentialProfile {
            id: cred_id,
            name: "bw".into(),
            kind: CredentialKind::Password,
            protocol: ProtocolType::Ssh,
            secret_provider: CredentialSecretProvider::Bitwarden,
            bitwarden_item_id: Some("item-1".into()),
            created_at: Utc::now(),
            username: None,
            domain: None,
            private_key_file_name: None,
            bitwarden_item_name: None,
            bitwarden_field_path: None,
        });
        lab.store_credential_password(&cred_id, "must-not-export").unwrap();
        let payload = build_backup_payload(&lab, &lab).unwrap();
        assert!(payload.passwords.is_empty());
    }

    #[test]
    fn malformed_payload_array_fails_closed() {
        let doc = BackupDocument {
            schema_version: CURRENT_SCHEMA_VERSION,
            app: "Wormhole".into(),
            exported_at: Utc::now().to_rfc3339(),
            encryption: encryption::NONE.into(),
            payload: Some(crate::backup::BackupPayload {
                nodes: vec![serde_json::json!({"not": "a node"})],
                ..Default::default()
            }),
            encrypted_payload: None,
        };
        let json = serde_json::to_string(&doc).unwrap();
        let err = parse_backup_payload(&json, None).unwrap_err();
        assert!(err.to_string().contains("malformed"), "{err}");
    }

    #[test]
    fn inspect_does_not_require_password_bodies() {
        let (src, ..) = sample_lab();
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("plain.json");
        export_backup(&path, &src, &src, None).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        let info = inspect_backup_json(&text).unwrap();
        assert!(!info.encrypted);
        assert_eq!(info.schema_version, CURRENT_SCHEMA_VERSION);
    }

    #[test]
    fn storage_sqlite_roundtrip() {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("wormhole.db");
        let factory = SqliteConnectionFactory::new(&db_path);
        MigrationRunner::embedded().run(&factory).unwrap();

        let cred_id = Uuid::new_v4();
        let node_id = Uuid::new_v4();
        {
            let cred_repo = CredentialRepository::new(&factory);
            cred_repo
                .insert(CredentialProfile {
                    id: cred_id,
                    name: "lab".into(),
                    username: None,
                    domain: None,
                    kind: CredentialKind::Password,
                    private_key_file_name: None,
                    protocol: ProtocolType::Ssh,
                    secret_provider: CredentialSecretProvider::Local,
                    bitwarden_item_id: None,
                    bitwarden_item_name: None,
                    bitwarden_field_path: None,
                    created_at: Utc::now(),
                })
                .unwrap();
            let conn_repo = ConnectionRepository::new(&factory);
            conn_repo
                .insert(&ConnectionNode {
                    id: node_id,
                    name: "host".into(),
                    kind: NodeKind::Connection,
                    protocol: Some(ProtocolType::Ssh),
                    host: Some("h".into()),
                    credential_id: Some(cred_id),
                    ..Default::default()
                })
                .unwrap();
        }

        let secrets = FakeBackupLab::new();
        secrets.store_credential_password(&cred_id, "pw").unwrap();

        let path = dir.path().join("storage-backup.json");
        {
            let source = StorageBackupSource {
                connections: ConnectionRepository::new(&factory),
                credentials: CredentialRepository::new(&factory),
                tunnels: TunnelConfigRepository::new(&factory),
            };
            export_backup(&path, &source, &secrets, None).unwrap();
        }

        let dst_dir = TempDir::new().unwrap();
        let dst_db = dst_dir.path().join("wormhole.db");
        let dst_factory = SqliteConnectionFactory::new(&dst_db);
        MigrationRunner::embedded().run(&dst_factory).unwrap();
        let dst_secrets = FakeBackupLab::new();
        {
            let sink = StorageBackupSink {
                connections: ConnectionRepository::new(&dst_factory),
                credentials: CredentialRepository::new(&dst_factory),
                tunnels: TunnelConfigRepository::new(&dst_factory),
            };
            import_backup(&path, &sink, &dst_secrets, None).unwrap();
        }
        assert_eq!(
            dst_secrets.read_credential_password(&cred_id).unwrap().as_deref(),
            Some("pw")
        );
        let nodes = ConnectionRepository::new(&dst_factory).list_all().unwrap();
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].node.id, node_id);
    }
}
