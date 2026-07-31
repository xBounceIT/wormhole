//! Stable virtual credential ids for Bitwarden cache rows (C# `BitwardenVirtualCredentialIds`).
//!
//! SHA-256 over `wormhole-bitwarden-virtual-credential-v1:{Protocol}:{itemId}`; first 16 bytes
//! become a .NET-style [`Uuid`] (mixed-endian `Guid` layout). **Metadata only** — never
//! passwords or session keys.

use sha2::{Digest, Sha256};
use uuid::Uuid;
use wormhole_domain::ProtocolType;

/// Namespace prefix (C# `BitwardenVirtualCredentialIds.Namespace`).
pub const BITWARDEN_VIRTUAL_CREDENTIAL_NAMESPACE: &str = "wormhole-bitwarden-virtual-credential-v1";

/// Errors from virtual-id helpers (no secret payloads).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BitwardenVirtualIdError {
    /// Blank / whitespace item id.
    #[error("Bitwarden item id is required")]
    EmptyItemId,
}

/// Derive the stable virtual credential id for a cache item + protocol.
///
/// `item_id` is trimmed; blank ids fail closed. `protocol` uses C# `ProtocolType.ToString()`
/// (`Ssh` / `Rdp` / `Vnc`).
pub fn bitwarden_virtual_credential_id(
    item_id: &str,
    protocol: ProtocolType,
) -> Result<Uuid, BitwardenVirtualIdError> {
    let trimmed = item_id.trim();
    if trimmed.is_empty() {
        return Err(BitwardenVirtualIdError::EmptyItemId);
    }
    let material = format!("{BITWARDEN_VIRTUAL_CREDENTIAL_NAMESPACE}:{protocol}:{trimmed}");
    let hash = Sha256::digest(material.as_bytes());
    Ok(dotnet_guid_from_sha256_prefix(&hash))
}

/// Ensure per-protocol virtual ids on a cache entry (fills only empty / nil slots).
pub fn ensure_cache_entry_ids(entry: &mut BitwardenCredentialCacheEntry) {
    if entry.ssh_credential_id.is_nil() {
        entry.ssh_credential_id =
            bitwarden_virtual_credential_id(&entry.item_id, ProtocolType::Ssh)
                .unwrap_or(Uuid::nil());
    }
    if entry.rdp_credential_id.is_nil() {
        entry.rdp_credential_id =
            bitwarden_virtual_credential_id(&entry.item_id, ProtocolType::Rdp)
                .unwrap_or(Uuid::nil());
    }
    if entry.vnc_credential_id.is_nil() {
        entry.vnc_credential_id =
            bitwarden_virtual_credential_id(&entry.item_id, ProtocolType::Vnc)
                .unwrap_or(Uuid::nil());
    }
}

/// Metadata-only Bitwarden login cache row (C# `BitwardenCredentialCacheEntry`).
///
/// Passwords are **never** stored here — display cache + virtual id anchors only.
#[derive(Clone, PartialEq, Eq)]
pub struct BitwardenCredentialCacheEntry {
    /// Bitwarden login item id (primary key in SQLite cache).
    pub item_id: String,
    /// Stable virtual credential id for SSH picker rows.
    pub ssh_credential_id: Uuid,
    /// Stable virtual credential id for RDP picker rows.
    pub rdp_credential_id: Uuid,
    /// Stable virtual credential id for VNC picker rows.
    pub vnc_credential_id: Uuid,
    /// Display name from vault sync.
    pub name: String,
    /// Login username metadata.
    pub username: Option<String>,
    /// Optional Bitwarden revision date string.
    pub revision_date: Option<String>,
    /// Last full-sync timestamp.
    pub last_seen_sync_utc: chrono::DateTime<chrono::Utc>,
    /// Row updated timestamp.
    pub updated_at_utc: chrono::DateTime<chrono::Utc>,
}

impl BitwardenCredentialCacheEntry {
    /// Construct a row and assign stable virtual ids (C# `EnsureIds`).
    pub fn new(
        item_id: impl Into<String>,
        name: impl Into<String>,
        username: Option<String>,
    ) -> Self {
        let item_id = item_id.into();
        let now = chrono::Utc::now();
        let mut entry = Self {
            item_id,
            ssh_credential_id: Uuid::nil(),
            rdp_credential_id: Uuid::nil(),
            vnc_credential_id: Uuid::nil(),
            name: name.into(),
            username,
            revision_date: None,
            last_seen_sync_utc: now,
            updated_at_utc: now,
        };
        ensure_cache_entry_ids(&mut entry);
        entry
    }

    /// Virtual credential id for `protocol` (C# `GetCredentialId`).
    pub fn credential_id(&self, protocol: ProtocolType) -> Option<Uuid> {
        let id = match protocol {
            ProtocolType::Ssh => self.ssh_credential_id,
            ProtocolType::Rdp => self.rdp_credential_id,
            ProtocolType::Vnc => self.vnc_credential_id,
            _ => return None,
        };
        (!id.is_nil()).then_some(id)
    }
}

impl std::fmt::Debug for BitwardenCredentialCacheEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BitwardenCredentialCacheEntry")
            .field("item_id", &self.item_id)
            .field("name", &self.name)
            .field("username", &self.username)
            .field("revision_date", &self.revision_date)
            .field("last_seen_sync_utc", &self.last_seen_sync_utc)
            .field("updated_at_utc", &self.updated_at_utc)
            .finish()
    }
}

fn dotnet_guid_from_sha256_prefix(hash: &[u8]) -> Uuid {
    let b = &hash[..16];
    Uuid::from_fields(
        u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
        u16::from_le_bytes([b[4], b[5]]),
        u16::from_le_bytes([b[6], b[7]]),
        &[
            b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15],
        ],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn virtual_ids_are_stable_per_item_and_protocol() {
        let ssh1 =
            bitwarden_virtual_credential_id("item-1", ProtocolType::Ssh).expect("ssh");
        let ssh2 =
            bitwarden_virtual_credential_id("item-1", ProtocolType::Ssh).expect("ssh");
        let rdp =
            bitwarden_virtual_credential_id("item-1", ProtocolType::Rdp).expect("rdp");
        assert_eq!(ssh1, ssh2);
        assert_ne!(ssh1, rdp);
    }

    #[test]
    fn virtual_ids_match_csharp_sha256_layout() {
        assert_eq!(
            bitwarden_virtual_credential_id("item-1", ProtocolType::Ssh).unwrap(),
            Uuid::parse_str("e3753518-250f-9e77-0a7d-55f1ff7bac30").unwrap()
        );
        assert_eq!(
            bitwarden_virtual_credential_id("item-1", ProtocolType::Rdp).unwrap(),
            Uuid::parse_str("ce5ff631-93a3-1ec1-9fb3-e14dda13519c").unwrap()
        );
        assert_eq!(
            bitwarden_virtual_credential_id("item-1", ProtocolType::Vnc).unwrap(),
            Uuid::parse_str("9e9a0857-4971-5beb-acef-cd9c14228169").unwrap()
        );
    }

    #[test]
    fn blank_item_id_fails_closed() {
        assert!(matches!(
            bitwarden_virtual_credential_id("", ProtocolType::Ssh),
            Err(BitwardenVirtualIdError::EmptyItemId)
        ));
        assert!(matches!(
            bitwarden_virtual_credential_id("   ", ProtocolType::Ssh),
            Err(BitwardenVirtualIdError::EmptyItemId)
        ));
    }

    #[test]
    fn ensure_ids_fills_empty_slots_only() {
        let mut entry = BitwardenCredentialCacheEntry::new("router", "Router", Some("admin".into()));
        let ssh = entry.ssh_credential_id;
        entry.rdp_credential_id = Uuid::new_v4();
        let pinned_rdp = entry.rdp_credential_id;
        ensure_cache_entry_ids(&mut entry);
        assert_eq!(entry.ssh_credential_id, ssh);
        assert_eq!(entry.rdp_credential_id, pinned_rdp);
        assert!(!entry.vnc_credential_id.is_nil());
    }

    #[test]
    fn cache_entry_debug_omits_password_shaped_fields() {
        let entry = BitwardenCredentialCacheEntry::new("item", "Lab", Some("root".into()));
        let dbg = format!("{entry:?}");
        assert!(dbg.contains("Lab"));
        assert!(!dbg.to_lowercase().contains("password"));
        assert!(!dbg.contains("ssh_credential_id"));
    }
}
