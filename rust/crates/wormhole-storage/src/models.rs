//! Persistence row wrappers around [`wormhole_domain`] types.
//!
//! Domain models omit SQLite audit columns (`CreatedAt` / `UpdatedAt`); those
//! live here on [`StoredConnectionNode`]. [`TunnelConfig`] keeps timestamps on
//! the row itself because `UpdatedAt` is caller-controlled on update (pool
//! invalidation).

use chrono::{DateTime, Utc};
use uuid::Uuid;
use wormhole_domain::{ConnectionNode, TunnelKind};

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
