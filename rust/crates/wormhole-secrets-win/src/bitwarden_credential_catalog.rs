//! Bitwarden virtual credential catalog Fake glue (C# `BitwardenCredentialCatalogService`).
//!
//! Merges local credential metadata with read-only **virtual** Bitwarden rows projected
//! from the SQLite display cache. Lab hosts inject [`FakeLocalCredentialCatalog`] /
//! [`FakeBitwardenCredentialCache`] — **no** live `bw` CLI spawn, no password bodies.
//!
//! Fail-closed: when the vault toggle is on but [`BitwardenSession`] is
//! [`BitwardenSessionStatus::Locked`], cache reads return **empty** and virtual rows are
//! not merged (local profiles still listed). Disabled vault → local profiles only
//! (C# `EnableBitwardenVault == false`).

use std::fmt;
use std::sync::Mutex;

use chrono::{DateTime, Utc};
use uuid::Uuid;
use wormhole_domain::{
    CredentialKind, CredentialSecretProvider, ProtocolType, BITWARDEN_PASSWORD_FIELD_PATH,
};

use crate::bitwarden_session::{BitwardenSession, BitwardenSessionStatus};
use crate::bitwarden_virtual_credential_ids::{
    ensure_cache_entry_ids, BitwardenCredentialCacheEntry,
};

/// Protocols that receive per-item virtual credentials (C# `VirtualProtocols`).
pub const BITWARDEN_VIRTUAL_PROTOCOLS: &[ProtocolType] =
    &[ProtocolType::Ssh, ProtocolType::Rdp, ProtocolType::Vnc];

/// Catalog profile row (C# `CredentialProfile` + `IsVirtualBitwarden`).
///
/// Metadata only — never password / private-key / session-key material.
#[derive(Clone, PartialEq, Eq)]
pub struct BitwardenCatalogProfile {
    /// Stable credential id (local row or virtual SHA-256 id).
    pub id: Uuid,
    /// Display name.
    pub name: String,
    /// Login username (metadata).
    pub username: Option<String>,
    /// Optional RDP domain.
    pub domain: Option<String>,
    /// Password vs SSH key kind.
    pub kind: CredentialKind,
    /// Private-key filename pointer only (not key bytes).
    pub private_key_file_name: Option<String>,
    /// Session protocol for this row.
    pub protocol: ProtocolType,
    /// Local CredMgr vs Bitwarden vault reference.
    pub secret_provider: CredentialSecretProvider,
    /// Bitwarden item id when provider is Bitwarden.
    pub bitwarden_item_id: Option<String>,
    /// Cached Bitwarden item display name.
    pub bitwarden_item_name: Option<String>,
    /// Bitwarden field path (default `login.password`).
    pub bitwarden_field_path: Option<String>,
    /// Created / cache-updated timestamp.
    pub created_at: DateTime<Utc>,
    /// Read-only virtual row projected from cache (not in `CredentialProfiles`).
    pub is_virtual_bitwarden: bool,
}

impl BitwardenCatalogProfile {
    /// Local (non-virtual) profile for tests / adapters.
    pub fn local_password(
        id: Uuid,
        name: impl Into<String>,
        protocol: ProtocolType,
        username: Option<String>,
    ) -> Self {
        Self {
            id,
            name: name.into(),
            username,
            domain: None,
            kind: CredentialKind::Password,
            private_key_file_name: None,
            protocol,
            secret_provider: CredentialSecretProvider::Local,
            bitwarden_item_id: None,
            bitwarden_item_name: None,
            bitwarden_field_path: Some(BITWARDEN_PASSWORD_FIELD_PATH.to_owned()),
            created_at: Utc::now(),
            is_virtual_bitwarden: false,
        }
    }

    /// Linked Bitwarden credential saved in SQLite (non-virtual).
    pub fn linked_bitwarden(
        id: Uuid,
        name: impl Into<String>,
        protocol: ProtocolType,
        item_id: impl Into<String>,
        username: Option<String>,
    ) -> Self {
        let name = name.into();
        let item_id = item_id.into();
        Self {
            id,
            name: name.clone(),
            username,
            domain: None,
            kind: CredentialKind::Password,
            private_key_file_name: None,
            protocol,
            secret_provider: CredentialSecretProvider::Bitwarden,
            bitwarden_item_id: Some(item_id.clone()),
            bitwarden_item_name: Some(name),
            bitwarden_field_path: Some(BITWARDEN_PASSWORD_FIELD_PATH.to_owned()),
            created_at: Utc::now(),
            is_virtual_bitwarden: false,
        }
    }
}

impl fmt::Debug for BitwardenCatalogProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BitwardenCatalogProfile")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("username", &self.username)
            .field("domain", &self.domain)
            .field("kind", &self.kind)
            .field("protocol", &self.protocol)
            .field("secret_provider", &self.secret_provider)
            .field("bitwarden_item_id", &self.bitwarden_item_id)
            .field("is_virtual_bitwarden", &self.is_virtual_bitwarden)
            .finish()
    }
}

/// Errors from catalog load / merge (never carry secrets).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BitwardenCatalogError {
    /// Local credential metadata load failed.
    #[error("failed to load local credentials: {0}")]
    LocalLoad(String),
    /// Bitwarden display-cache load failed.
    #[error("failed to load Bitwarden credential cache: {0}")]
    CacheLoad(String),
}

/// Local credential metadata source (SQLite adapter or Fake).
pub trait LocalCredentialCatalog: Send + Sync {
    /// All saved credential profiles (no virtual rows).
    fn list_all(&self) -> Result<Vec<BitwardenCatalogProfile>, BitwardenCatalogError>;
    /// Lookup by id in local storage only.
    fn get_by_id(&self, id: Uuid) -> Result<Option<BitwardenCatalogProfile>, BitwardenCatalogError>;
}

/// Bitwarden display-cache source (SQLite adapter or Fake).
pub trait BitwardenCredentialCacheSource: Send + Sync {
    /// Cached login items (metadata only).
    fn list_all(&self) -> Result<Vec<BitwardenCredentialCacheEntry>, BitwardenCatalogError>;
}

/// Catalog orchestrator (C# `BitwardenCredentialCatalogService`).
pub struct BitwardenCredentialCatalogGlue<L, C, S>
where
    L: LocalCredentialCatalog,
    C: BitwardenCredentialCacheSource,
    S: BitwardenSession,
{
    local: L,
    cache: C,
    session: S,
    vault_enabled: bool,
}

impl<L, C, S> fmt::Debug for BitwardenCredentialCatalogGlue<L, C, S>
where
    L: LocalCredentialCatalog,
    C: BitwardenCredentialCacheSource,
    S: BitwardenSession,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BitwardenCredentialCatalogGlue")
            .field("vault_enabled", &self.vault_enabled)
            .field("session_status", &self.session.status())
            .finish()
    }
}

impl<L, C, S> BitwardenCredentialCatalogGlue<L, C, S>
where
    L: LocalCredentialCatalog,
    C: BitwardenCredentialCacheSource,
    S: BitwardenSession,
{
    /// Construct glue with injectable local catalog, cache, session, and settings flag.
    pub fn new(local: L, cache: C, session: S, vault_enabled: bool) -> Self {
        Self {
            local,
            cache,
            session,
            vault_enabled,
        }
    }

    /// Credentials page list (C# `GetCredentialPageProfilesAsync`).
    pub fn credential_page_profiles(&self) -> Result<Vec<BitwardenCatalogProfile>, BitwardenCatalogError> {
        let local = self.local.list_all()?;
        if !self.vault_enabled {
            return Ok(sort_by_name(local));
        }
        let entries = self.load_cache_entries()?;
        let linked_item_ids = linked_bitwarden_item_ids(&local);
        let mut profiles = local;
        for entry in entries {
            if linked_item_ids.iter().any(|id| id == entry.item_id.trim()) {
                continue;
            }
            profiles.push(project(&entry, ProtocolType::Ssh, true));
        }
        Ok(sort_by_name(profiles))
    }

    /// Picker list — local + virtual per protocol (C# `GetPickerProfilesAsync`).
    pub fn picker_profiles(&self) -> Result<Vec<BitwardenCatalogProfile>, BitwardenCatalogError> {
        let local = self.local.list_all()?;
        if !self.vault_enabled {
            return Ok(sort_by_name(local));
        }
        let entries = self.load_cache_entries()?;
        let mut profiles = local.clone();
        add_virtual_profiles(&mut profiles, &local, &entries, None);
        Ok(sort_by_name(profiles))
    }

    /// Protocol-filtered picker (C# `GetProfilesForProtocolAsync`).
    pub fn profiles_for_protocol(
        &self,
        protocol: ProtocolType,
    ) -> Result<Vec<BitwardenCatalogProfile>, BitwardenCatalogError> {
        let local = self.local.list_all()?;
        let mut local_for_protocol: Vec<_> = local
            .iter()
            .filter(|c| c.protocol == protocol)
            .cloned()
            .collect();
        if !self.vault_enabled || !is_virtual_protocol(protocol) {
            sort_by_name_in_place(&mut local_for_protocol);
            return Ok(local_for_protocol);
        }
        let entries = self.load_cache_entries()?;
        add_virtual_profiles(
            &mut local_for_protocol,
            &local,
            &entries,
            Some(protocol),
        );
        sort_by_name_in_place(&mut local_for_protocol);
        Ok(local_for_protocol)
    }

    /// Resolve by id — local first, then virtual cache (C# `GetByIdAsync`).
    pub fn get_by_id(&self, id: Uuid) -> Result<Option<BitwardenCatalogProfile>, BitwardenCatalogError> {
        if let Some(local) = self.local.get_by_id(id)? {
            return Ok(Some(local));
        }
        if !self.vault_enabled {
            return Ok(None);
        }
        let entries = self.load_cache_entries()?;
        for entry in entries {
            for protocol in BITWARDEN_VIRTUAL_PROTOCOLS {
                if entry.credential_id(*protocol) == Some(id) {
                    return Ok(Some(project(&entry, *protocol, false)));
                }
            }
        }
        Ok(None)
    }

    fn load_cache_entries(&self) -> Result<Vec<BitwardenCredentialCacheEntry>, BitwardenCatalogError> {
        if !self.vault_enabled {
            return Ok(Vec::new());
        }
        if self.session.status() == BitwardenSessionStatus::Locked {
            // Fail-closed: no virtual rows; local profiles still served by callers.
            return Ok(Vec::new());
        }
        self.cache.list_all()
    }
}

fn is_virtual_protocol(protocol: ProtocolType) -> bool {
    matches!(
        protocol,
        ProtocolType::Ssh | ProtocolType::Rdp | ProtocolType::Vnc
    )
}

fn linked_bitwarden_item_ids(local: &[BitwardenCatalogProfile]) -> Vec<String> {
    let mut ids = Vec::new();
    for credential in local {
        if credential.secret_provider != CredentialSecretProvider::Bitwarden {
            continue;
        }
        let Some(item_id) = credential.bitwarden_item_id.as_deref() else {
            continue;
        };
        let trimmed = item_id.trim();
        if !trimmed.is_empty() {
            ids.push(trimmed.to_owned());
        }
    }
    ids
}

fn linked_protocol_item_pairs(local: &[BitwardenCatalogProfile]) -> Vec<(ProtocolType, String)> {
    let mut linked = Vec::new();
    for credential in local {
        if credential.secret_provider != CredentialSecretProvider::Bitwarden {
            continue;
        }
        let Some(item_id) = credential.bitwarden_item_id.as_deref() else {
            continue;
        };
        let trimmed = item_id.trim();
        if trimmed.is_empty() {
            continue;
        }
        linked.push((credential.protocol, trimmed.to_owned()));
    }
    linked
}

fn add_virtual_profiles(
    target: &mut Vec<BitwardenCatalogProfile>,
    local: &[BitwardenCatalogProfile],
    entries: &[BitwardenCredentialCacheEntry],
    protocol_filter: Option<ProtocolType>,
) {
    let linked = linked_protocol_item_pairs(local);
    for entry in entries {
        for protocol in BITWARDEN_VIRTUAL_PROTOCOLS {
            if let Some(filter) = protocol_filter {
                if *protocol != filter {
                    continue;
                }
            }
            if linked.contains(&( *protocol, entry.item_id.clone())) {
                continue;
            }
            target.push(project(entry, *protocol, false));
        }
    }
}

fn project(
    entry: &BitwardenCredentialCacheEntry,
    protocol: ProtocolType,
    page_projection: bool,
) -> BitwardenCatalogProfile {
    let mut entry = entry.clone();
    ensure_cache_entry_ids(&mut entry);
    let id = entry
        .credential_id(protocol)
        .unwrap_or_else(Uuid::nil);
    BitwardenCatalogProfile {
        id,
        name: entry.name.clone(),
        username: entry.username.clone(),
        domain: None,
        kind: CredentialKind::Password,
        private_key_file_name: None,
        protocol: if page_projection {
            ProtocolType::Ssh
        } else {
            protocol
        },
        secret_provider: CredentialSecretProvider::Bitwarden,
        bitwarden_item_id: Some(entry.item_id.clone()),
        bitwarden_item_name: Some(entry.name.clone()),
        bitwarden_field_path: Some(BITWARDEN_PASSWORD_FIELD_PATH.to_owned()),
        created_at: entry.updated_at_utc,
        is_virtual_bitwarden: true,
    }
}

fn sort_by_name(mut profiles: Vec<BitwardenCatalogProfile>) -> Vec<BitwardenCatalogProfile> {
    sort_by_name_in_place(&mut profiles);
    profiles
}

fn sort_by_name_in_place(profiles: &mut [BitwardenCatalogProfile]) {
    profiles.sort_by(|a, b| a.name.cmp(&b.name));
}

/// Demo cache rows for picker / lab (metadata only — no passwords).
pub fn demo_bitwarden_cache_entries() -> Vec<BitwardenCredentialCacheEntry> {
    vec![
        BitwardenCredentialCacheEntry::new("lab-router", "Lab Router", Some("admin".into())),
        BitwardenCredentialCacheEntry::new("lab-server", "Lab Server", Some("root".into())),
        BitwardenCredentialCacheEntry::new("lab-switch", "Lab Switch", Some("netops".into())),
    ]
}

#[derive(Default)]
struct FakeLocalInner {
    profiles: Vec<BitwardenCatalogProfile>,
    fail: Option<String>,
}

/// In-memory local credential catalog (tests / lab).
#[derive(Default)]
pub struct FakeLocalCredentialCatalog {
    inner: Mutex<FakeLocalInner>,
}

impl FakeLocalCredentialCatalog {
    /// Empty successful catalog.
    pub fn new() -> Self {
        Self::default()
    }

    /// Seeded local profiles (order preserved).
    pub fn with_profiles(profiles: impl IntoIterator<Item = BitwardenCatalogProfile>) -> Self {
        Self {
            inner: Mutex::new(FakeLocalInner {
                profiles: profiles.into_iter().collect(),
                fail: None,
            }),
        }
    }

    /// Always fail local loads with the given message.
    pub fn failing(message: impl Into<String>) -> Self {
        Self {
            inner: Mutex::new(FakeLocalInner {
                profiles: Vec::new(),
                fail: Some(message.into()),
            }),
        }
    }
}

impl fmt::Debug for FakeLocalCredentialCatalog {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let guard = self.inner.lock().expect("mutex");
        f.debug_struct("FakeLocalCredentialCatalog")
            .field("len", &guard.profiles.len())
            .field("failing", &guard.fail.is_some())
            .finish()
    }
}

impl LocalCredentialCatalog for FakeLocalCredentialCatalog {
    fn list_all(&self) -> Result<Vec<BitwardenCatalogProfile>, BitwardenCatalogError> {
        let guard = self.inner.lock().expect("mutex");
        if let Some(msg) = &guard.fail {
            return Err(BitwardenCatalogError::LocalLoad(msg.clone()));
        }
        Ok(guard.profiles.clone())
    }

    fn get_by_id(&self, id: Uuid) -> Result<Option<BitwardenCatalogProfile>, BitwardenCatalogError> {
        Ok(self
            .list_all()?
            .into_iter()
            .find(|p| p.id == id))
    }
}

impl LocalCredentialCatalog for &FakeLocalCredentialCatalog {
    fn list_all(&self) -> Result<Vec<BitwardenCatalogProfile>, BitwardenCatalogError> {
        (*self).list_all()
    }

    fn get_by_id(&self, id: Uuid) -> Result<Option<BitwardenCatalogProfile>, BitwardenCatalogError> {
        (*self).get_by_id(id)
    }
}

#[derive(Default)]
struct FakeCacheInner {
    entries: Vec<BitwardenCredentialCacheEntry>,
    fail: Option<String>,
    locked_empty: bool,
}

/// In-memory Bitwarden display cache (tests / lab; no `bw` sync).
#[derive(Default)]
pub struct FakeBitwardenCredentialCache {
    inner: Mutex<FakeCacheInner>,
}

impl FakeBitwardenCredentialCache {
    /// Empty successful cache.
    pub fn new() -> Self {
        Self::default()
    }

    /// Lab demo rows ([`demo_bitwarden_cache_entries`]).
    pub fn with_demo_entries() -> Self {
        Self::with_entries(demo_bitwarden_cache_entries())
    }

    /// Seeded cache entries (metadata only).
    pub fn with_entries(entries: impl IntoIterator<Item = BitwardenCredentialCacheEntry>) -> Self {
        Self {
            inner: Mutex::new(FakeCacheInner {
                entries: entries.into_iter().collect(),
                fail: None,
                locked_empty: false,
            }),
        }
    }

    /// Always fail cache loads with the given message.
    pub fn failing(message: impl Into<String>) -> Self {
        Self {
            inner: Mutex::new(FakeCacheInner {
                entries: Vec::new(),
                fail: Some(message.into()),
                locked_empty: false,
            }),
        }
    }

    /// When set, `list_all` returns empty (locked-vault lab mode).
    pub fn locked_fail_closed_empty(&self) {
        let mut guard = self.inner.lock().expect("mutex");
        guard.locked_empty = true;
        guard.entries.clear();
    }
}

impl fmt::Debug for FakeBitwardenCredentialCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let guard = self.inner.lock().expect("mutex");
        f.debug_struct("FakeBitwardenCredentialCache")
            .field("len", &guard.entries.len())
            .field("failing", &guard.fail.is_some())
            .field("locked_empty", &guard.locked_empty)
            .finish()
    }
}

impl BitwardenCredentialCacheSource for FakeBitwardenCredentialCache {
    fn list_all(&self) -> Result<Vec<BitwardenCredentialCacheEntry>, BitwardenCatalogError> {
        let guard = self.inner.lock().expect("mutex");
        if let Some(msg) = &guard.fail {
            return Err(BitwardenCatalogError::CacheLoad(msg.clone()));
        }
        if guard.locked_empty {
            return Ok(Vec::new());
        }
        Ok(guard.entries.clone())
    }
}

impl BitwardenCredentialCacheSource for &FakeBitwardenCredentialCache {
    fn list_all(&self) -> Result<Vec<BitwardenCredentialCacheEntry>, BitwardenCatalogError> {
        (*self).list_all()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bitwarden_virtual_credential_id;
    use crate::{FakeBitwardenSession, StubBitwardenSession};

    fn cache(item_id: &str, name: &str, username: &str) -> BitwardenCredentialCacheEntry {
        BitwardenCredentialCacheEntry::new(item_id, name, Some(username.into()))
    }

    type TestGlue = BitwardenCredentialCatalogGlue<
        FakeLocalCredentialCatalog,
        FakeBitwardenCredentialCache,
        FakeBitwardenSession,
    >;

    fn unlocked_session() -> FakeBitwardenSession {
        let session = FakeBitwardenSession::with_session_key("opaque-lab-session");
        assert!(session.unlock("lab-password").unlocked);
        session
    }

    fn enabled_glue(
        local: FakeLocalCredentialCatalog,
        cache: FakeBitwardenCredentialCache,
    ) -> TestGlue {
        BitwardenCredentialCatalogGlue::new(local, cache, unlocked_session(), true)
    }

    #[test]
    fn virtual_ids_stable_across_calls() {
        let a = bitwarden_virtual_credential_id("item-1", ProtocolType::Ssh).unwrap();
        let b = bitwarden_virtual_credential_id("item-1", ProtocolType::Ssh).unwrap();
        assert_eq!(a, b);
        assert_ne!(
            a,
            bitwarden_virtual_credential_id("item-1", ProtocolType::Rdp).unwrap()
        );
    }

    #[test]
    fn profiles_for_protocol_projects_cache_and_hides_linked_duplicate() {
        let linked = BitwardenCatalogProfile::linked_bitwarden(
            Uuid::new_v4(),
            "Router local link",
            ProtocolType::Rdp,
            "router",
            Some("admin".into()),
        );
        let local = FakeLocalCredentialCatalog::with_profiles([linked.clone()]);
        let cache = FakeBitwardenCredentialCache::with_entries([
            cache("router", "Router", "admin"),
            cache("server", "Server", "root"),
        ]);
        let glue = enabled_glue(local, cache);

        let rdp = glue.profiles_for_protocol(ProtocolType::Rdp).unwrap();
        let ssh = glue.profiles_for_protocol(ProtocolType::Ssh).unwrap();

        assert!(rdp.iter().any(|c| c.id == linked.id));
        assert!(!rdp.iter().any(|c| c.is_virtual_bitwarden && c.bitwarden_item_id.as_deref() == Some("router")));
        let server = rdp
            .iter()
            .find(|c| c.is_virtual_bitwarden && c.bitwarden_item_id.as_deref() == Some("server"))
            .expect("server virtual");
        assert_eq!(server.protocol, ProtocolType::Rdp);
        assert_eq!(server.secret_provider, CredentialSecretProvider::Bitwarden);
        assert_eq!(server.username.as_deref(), Some("root"));

        assert!(ssh.iter().any(|c| c.is_virtual_bitwarden && c.bitwarden_item_id.as_deref() == Some("router")));
    }

    #[test]
    fn get_by_id_resolves_virtual_from_cache() {
        let entry = cache("server", "Server", "root");
        let expected_id = entry.rdp_credential_id;
        let glue = enabled_glue(
            FakeLocalCredentialCatalog::new(),
            FakeBitwardenCredentialCache::with_entries([entry]),
        );

        let profile = glue.get_by_id(expected_id).unwrap().expect("virtual");
        assert!(profile.is_virtual_bitwarden);
        assert_eq!(profile.protocol, ProtocolType::Rdp);
        assert_eq!(profile.bitwarden_item_id.as_deref(), Some("server"));
        assert_eq!(
            profile.bitwarden_field_path.as_deref(),
            Some(BITWARDEN_PASSWORD_FIELD_PATH)
        );
    }

    #[test]
    fn vault_disabled_returns_local_only() {
        let local = FakeLocalCredentialCatalog::with_profiles([BitwardenCatalogProfile::local_password(
            Uuid::new_v4(),
            "local-only",
            ProtocolType::Ssh,
            None,
        )]);
        let glue = BitwardenCredentialCatalogGlue::new(
            local,
            FakeBitwardenCredentialCache::with_demo_entries(),
            StubBitwardenSession,
            false,
        );
        assert_eq!(glue.picker_profiles().unwrap().len(), 1);
        assert!(glue.picker_profiles().unwrap()[0].name == "local-only");
    }

    #[test]
    fn locked_vault_fail_closed_empty_virtual_rows_local_still_listed() {
        let local = FakeLocalCredentialCatalog::with_profiles([BitwardenCatalogProfile::local_password(
            Uuid::new_v4(),
            "saved-local",
            ProtocolType::Ssh,
            None,
        )]);
        let glue = BitwardenCredentialCatalogGlue::new(
            local,
            FakeBitwardenCredentialCache::with_demo_entries(),
            StubBitwardenSession,
            true,
        );
        let picker = glue.picker_profiles().unwrap();
        assert_eq!(picker.len(), 1);
        assert_eq!(picker[0].name, "saved-local");
        assert!(!picker.iter().any(|p| p.is_virtual_bitwarden));
        assert!(glue.credential_page_profiles().unwrap().len() == 1);
        assert!(glue.profiles_for_protocol(ProtocolType::Ssh).unwrap().len() == 1);
    }

    #[test]
    fn locked_vault_get_by_id_virtual_returns_none() {
        let entry = cache("server", "Server", "root");
        let virtual_id = entry.rdp_credential_id;
        let glue = BitwardenCredentialCatalogGlue::new(
            FakeLocalCredentialCatalog::new(),
            FakeBitwardenCredentialCache::with_entries([entry]),
            StubBitwardenSession,
            true,
        );
        assert_eq!(glue.get_by_id(virtual_id).unwrap(), None);
    }

    #[test]
    fn unlocked_vault_merges_demo_cache_into_picker() {
        let glue = enabled_glue(
            FakeLocalCredentialCatalog::new(),
            FakeBitwardenCredentialCache::with_demo_entries(),
        );
        let profiles = glue.picker_profiles().unwrap();
        assert!(profiles.len() >= 3 * BITWARDEN_VIRTUAL_PROTOCOLS.len());
        assert!(profiles.iter().any(|p| p.is_virtual_bitwarden && p.name == "Lab Router"));
    }

    #[test]
    fn credential_page_projects_ssh_only_for_unlinked_items() {
        let glue = enabled_glue(
            FakeLocalCredentialCatalog::new(),
            FakeBitwardenCredentialCache::with_entries([cache("solo", "Solo", "u")]),
        );
        let page = glue.credential_page_profiles().unwrap();
        let solo = page.iter().find(|p| p.bitwarden_item_id.as_deref() == Some("solo")).expect("solo");
        assert_eq!(solo.protocol, ProtocolType::Ssh);
        assert!(solo.is_virtual_bitwarden);
    }

    #[test]
    fn http_protocol_skips_virtual_merge_even_when_unlocked() {
        let glue = enabled_glue(
            FakeLocalCredentialCatalog::new(),
            FakeBitwardenCredentialCache::with_demo_entries(),
        );
        let http = glue.profiles_for_protocol(ProtocolType::Http).unwrap();
        assert!(http.is_empty());
    }

    #[test]
    fn demo_entries_contain_no_password_fields_in_debug() {
        for entry in demo_bitwarden_cache_entries() {
            let dbg = format!("{entry:?}");
            assert!(!dbg.to_lowercase().contains("password"));
            assert!(!dbg.to_lowercase().contains("hunter"));
        }
        let profile = project(&demo_bitwarden_cache_entries()[0], ProtocolType::Ssh, false);
        let dbg = format!("{profile:?}");
        assert!(!dbg.to_lowercase().contains("password:"));
    }

    #[test]
    fn fake_local_load_error_propagates() {
        let glue = BitwardenCredentialCatalogGlue::new(
            FakeLocalCredentialCatalog::failing("db down"),
            FakeBitwardenCredentialCache::with_demo_entries(),
            unlocked_session(),
            true,
        );
        assert!(matches!(
            glue.picker_profiles(),
            Err(BitwardenCatalogError::LocalLoad(_))
        ));
    }

    #[test]
    fn fake_cache_load_error_when_unlocked() {
        let glue = BitwardenCredentialCatalogGlue::new(
            FakeLocalCredentialCatalog::new(),
            FakeBitwardenCredentialCache::failing("cache io"),
            unlocked_session(),
            true,
        );
        assert!(matches!(
            glue.picker_profiles(),
            Err(BitwardenCatalogError::CacheLoad(_))
        ));
    }

    #[test]
    fn picker_sorted_by_name() {
        let glue = enabled_glue(
            FakeLocalCredentialCatalog::with_profiles([
                BitwardenCatalogProfile::local_password(Uuid::new_v4(), "zebra", ProtocolType::Ssh, None),
                BitwardenCatalogProfile::local_password(Uuid::new_v4(), "alpha", ProtocolType::Ssh, None),
            ]),
            FakeBitwardenCredentialCache::new(),
        );
        let names: Vec<_> = glue
            .picker_profiles()
            .unwrap()
            .into_iter()
            .map(|p| p.name)
            .collect();
        let mut sorted = names.clone();
        sorted.sort_by(|a, b| a.cmp(b));
        assert_eq!(names, sorted);
    }

    #[test]
    fn glue_debug_reports_status_not_secrets() {
        let glue = BitwardenCredentialCatalogGlue::new(
            FakeLocalCredentialCatalog::new(),
            FakeBitwardenCredentialCache::with_demo_entries(),
            unlocked_session(),
            true,
        );
        let dbg = format!("{glue:?}");
        assert!(dbg.contains("Unlocked"));
        assert!(!dbg.contains("super-secret"));
    }
}
