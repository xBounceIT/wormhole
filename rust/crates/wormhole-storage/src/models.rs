//! Persistence row wrappers around [`wormhole_domain`] types.
//!
//! Domain models omit SQLite audit columns (`CreatedAt` / `UpdatedAt`); those
//! live here on [`StoredConnectionNode`]. [`TunnelConfig`] keeps timestamps on
//! the row itself because `UpdatedAt` is caller-controlled on update (pool
//! invalidation). [`CredentialProfile`] is metadata-only (no password body).

use chrono::{DateTime, Utc};
use uuid::Uuid;
use wormhole_domain::{
    ConnectionNode, CredentialKind, CredentialSecretProvider, ProtocolType, TunnelKind,
};

/// A `Nodes` row: domain [`ConnectionNode`] plus persistence timestamps.
#[derive(Debug, Clone)]
pub struct StoredConnectionNode {
    pub node: ConnectionNode,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl StoredConnectionNode {
    pub fn is_folder(&self) -> bool {
        self.node.kind == wormhole_domain::NodeKind::Folder
    }

    pub fn is_connection(&self) -> bool {
        self.node.kind == wormhole_domain::NodeKind::Connection
    }
}

/// A `TunnelConfigs` metadata row (C# `Wormhole.Models.TunnelConfig`).
///
/// SQLite stores only Id / Name / Kind / timestamps. WireGuard keys, OpenVPN
/// profiles, Fortinet cookies, etc. live DPAPI-encrypted under
/// `%LOCALAPPDATA%\Wormhole\tunnels\` — never in this table.
#[derive(Debug, Clone)]
pub struct TunnelConfig {
    pub id: Uuid,
    pub name: String,
    pub kind: TunnelKind,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// A `CredentialProfiles` metadata row (C# `Wormhole.Models.CredentialProfile`).
///
/// SQLite stores identity / provider metadata only. Password bodies live in
/// CredMgr (`Wormhole:<guid:D>`); private-key bytes under `keys\<guid:N>.dpapi`.
/// `Debug` is safe — this type never carries secret bodies.
#[derive(Debug, Clone)]
pub struct CredentialProfile {
    pub id: Uuid,
    pub name: String,
    pub username: Option<String>,
    pub domain: Option<String>,
    pub kind: CredentialKind,
    /// Filename pointer only — not key material.
    pub private_key_file_name: Option<String>,
    pub protocol: ProtocolType,
    pub secret_provider: CredentialSecretProvider,
    pub bitwarden_item_id: Option<String>,
    pub bitwarden_item_name: Option<String>,
    pub bitwarden_field_path: Option<String>,
    pub created_at: DateTime<Utc>,
}

impl CredentialProfile {
    /// `SecretProvider == Bitwarden` (C# `IsBitwarden`).
    pub fn is_bitwarden(&self) -> bool {
        self.secret_provider == CredentialSecretProvider::Bitwarden
    }
}
