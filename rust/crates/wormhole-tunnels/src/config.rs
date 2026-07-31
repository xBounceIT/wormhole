use std::time::SystemTime;

use uuid::Uuid;

use crate::TunnelKind;

/// Minimal tunnel-config snapshot used by the manager skeleton.
///
/// Full `TunnelConfig` + DPAPI secret IO will land with storage/secrets crates.
#[derive(Debug, Clone)]
pub struct TunnelConfigSnapshot {
    pub id: Uuid,
    pub kind: TunnelKind,
    pub name: String,
    /// Mirrors C# `TunnelConfig.UpdatedAt` — edits bump this so pooled tunnels are evicted.
    pub updated_at: SystemTime,
}

impl TunnelConfigSnapshot {
    pub fn new(id: Uuid, kind: TunnelKind, name: impl Into<String>) -> Self {
        Self {
            id,
            kind,
            name: name.into(),
            updated_at: SystemTime::UNIX_EPOCH,
        }
    }
}
