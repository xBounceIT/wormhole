//! Tunnel configs page + tri-state picker Fake VM glue (C# `TunnelConfigsViewModel` /
//! `TunnelPickerViewModel` metadata subset).
//!
//! Lists tunnel config metadata via [`TunnelConfigSource`] (`FakeTunnelConfigList` in tests;
//! optional [`StorageTunnelConfigSource`] behind `--features storage`). Never loads DPAPI
//! payloads — secrets stay under `%LOCALAPPDATA%\Wormhole\tunnels\`. No GPUI chrome.
//!
//! Composes existing [`TunnelUiState`] for tri-state picker writes.

use std::collections::HashMap;
use std::fmt;
use std::sync::Mutex;

use chrono::{DateTime, Utc};
use thiserror::Error;
use uuid::Uuid;
use wormhole_domain::TunnelKind;

use crate::connection_editor::{TunnelUiSelection, TunnelUiState};

/// Fixed sentinel ids — must not collide with `Uuid::new_v4()` tunnel rows (C# parity).
pub const INHERIT_TUNNEL_ID: Uuid = Uuid::from_bytes([
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
]);
pub const NO_TUNNEL_ID: Uuid = Uuid::from_bytes([
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
]);

/// Errors from tunnel-config metadata list load (never secret payloads).
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum TunnelCatalogError {
    #[error("failed to load tunnel configs: {0}")]
    Load(String),
}

/// Metadata-only tunnel row for list / picker / editor selection.
///
/// `kind` and timestamps are `None` for inherit / no-tunnel sentinels. [`Debug`] is safe —
/// this type never carries DPAPI secret bodies.
#[derive(Clone, PartialEq, Eq)]
pub struct TunnelConfigRow {
    pub id: Uuid,
    pub name: String,
    pub kind: Option<TunnelKind>,
    pub created_at: Option<DateTime<Utc>>,
    pub updated_at: Option<DateTime<Utc>>,
}

impl TunnelConfigRow {
    pub fn config(
        id: Uuid,
        name: impl Into<String>,
        kind: TunnelKind,
        created_at: DateTime<Utc>,
        updated_at: DateTime<Utc>,
    ) -> Self {
        Self {
            id,
            name: name.into(),
            kind: Some(kind),
            created_at: Some(created_at),
            updated_at: Some(updated_at),
        }
    }

    pub fn sentinel(id: Uuid, name: impl Into<String>) -> Self {
        Self {
            id,
            name: name.into(),
            kind: None,
            created_at: None,
            updated_at: None,
        }
    }

    pub fn is_sentinel(&self) -> bool {
        is_sentinel_id(self.id)
    }
}

impl fmt::Debug for TunnelConfigRow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TunnelConfigRow")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("kind", &self.kind)
            .field("has_timestamps", &(self.created_at.is_some() && self.updated_at.is_some()))
            .finish()
    }
}

/// Loads tunnel config metadata (Fake in tests; SQLite repo with `storage`).
pub trait TunnelConfigSource {
    fn list_all(&self) -> Result<Vec<TunnelConfigRow>, TunnelCatalogError>;
}

/// In-memory Fake catalog for unit tests (no DPAPI / SQLite).
#[derive(Default)]
pub struct FakeTunnelConfigList {
    inner: Mutex<FakeTunnelConfigListInner>,
}

#[derive(Default)]
struct FakeTunnelConfigListInner {
    configs: Vec<TunnelConfigRow>,
    fail: Option<String>,
}

impl FakeTunnelConfigList {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_configs(configs: impl IntoIterator<Item = TunnelConfigRow>) -> Self {
        Self {
            inner: Mutex::new(FakeTunnelConfigListInner {
                configs: configs.into_iter().collect(),
                fail: None,
            }),
        }
    }

    pub fn failing(message: impl Into<String>) -> Self {
        Self {
            inner: Mutex::new(FakeTunnelConfigListInner {
                configs: Vec::new(),
                fail: Some(message.into()),
            }),
        }
    }

    pub fn set_configs(&self, configs: impl IntoIterator<Item = TunnelConfigRow>) {
        let mut guard = self.inner.lock().expect("FakeTunnelConfigList mutex poisoned");
        guard.configs = configs.into_iter().collect();
        guard.fail = None;
    }

    pub fn get_by_id(&self, id: Uuid) -> Result<Option<TunnelConfigRow>, TunnelCatalogError> {
        let guard = self.inner.lock().expect("FakeTunnelConfigList mutex poisoned");
        if let Some(msg) = &guard.fail {
            return Err(TunnelCatalogError::Load(msg.clone()));
        }
        Ok(guard.configs.iter().find(|r| r.id == id).cloned())
    }

    /// Lab CRUD: insert metadata row (payload via separate [`TunnelPayloadStore`]).
    pub fn insert_row(&self, row: TunnelConfigRow) -> Result<(), TunnelCatalogError> {
        let mut guard = self.inner.lock().expect("FakeTunnelConfigList mutex poisoned");
        if let Some(msg) = &guard.fail {
            return Err(TunnelCatalogError::Load(msg.clone()));
        }
        if row.is_sentinel() {
            return Err(TunnelCatalogError::Load("cannot insert sentinel row".into()));
        }
        let index = sorted_tunnel_index_for(&guard.configs, &row.name);
        guard.configs.insert(index, row);
        Ok(())
    }

    pub fn update_row(&self, updated: TunnelConfigRow) -> Result<(), TunnelCatalogError> {
        let mut guard = self.inner.lock().expect("FakeTunnelConfigList mutex poisoned");
        if let Some(msg) = &guard.fail {
            return Err(TunnelCatalogError::Load(msg.clone()));
        }
        if updated.is_sentinel() {
            return Err(TunnelCatalogError::Load("cannot update sentinel row".into()));
        }
        let Some(index) = guard.configs.iter().position(|r| r.id == updated.id) else {
            return Err(TunnelCatalogError::Load("tunnel config not found".into()));
        };
        if guard.configs[index].name != updated.name {
            guard.configs.remove(index);
            let insert_at = sorted_tunnel_index_for(&guard.configs, &updated.name);
            guard.configs.insert(insert_at, updated);
        } else {
            guard.configs[index] = updated;
        }
        Ok(())
    }

    pub fn delete_row(&self, id: Uuid) -> Result<(), TunnelCatalogError> {
        let mut guard = self.inner.lock().expect("FakeTunnelConfigList mutex poisoned");
        if let Some(msg) = &guard.fail {
            return Err(TunnelCatalogError::Load(msg.clone()));
        }
        let len_before = guard.configs.len();
        guard.configs.retain(|r| r.id != id);
        if guard.configs.len() == len_before {
            return Err(TunnelCatalogError::Load("tunnel config not found".into()));
        }
        Ok(())
    }
}

fn sorted_tunnel_index_for(rows: &[TunnelConfigRow], name: &str) -> usize {
    rows.iter()
        .position(|r| r.name.as_str() > name)
        .unwrap_or(rows.len())
}

/// C# `NameExists` — case-insensitive name collision check.
pub fn tunnel_name_exists(
    configs: &[TunnelConfigRow],
    name: &str,
    excluding_id: Option<Uuid>,
) -> bool {
    configs.iter().any(|c| {
        !c.is_sentinel()
            && excluding_id.map_or(true, |id| c.id != id)
            && c.name.eq_ignore_ascii_case(name)
    })
}

impl fmt::Debug for FakeTunnelConfigList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let guard = self.inner.lock().expect("FakeTunnelConfigList mutex poisoned");
        f.debug_struct("FakeTunnelConfigList")
            .field("len", &guard.configs.len())
            .field("failing", &guard.fail.is_some())
            .finish()
    }
}

impl TunnelConfigSource for FakeTunnelConfigList {
    fn list_all(&self) -> Result<Vec<TunnelConfigRow>, TunnelCatalogError> {
        let guard = self.inner.lock().expect("FakeTunnelConfigList mutex poisoned");
        if let Some(msg) = &guard.fail {
            return Err(TunnelCatalogError::Load(msg.clone()));
        }
        Ok(guard.configs.clone())
    }
}

impl TunnelConfigSource for &FakeTunnelConfigList {
    fn list_all(&self) -> Result<Vec<TunnelConfigRow>, TunnelCatalogError> {
        (*self).list_all()
    }
}

#[cfg(feature = "storage")]
pub struct StorageTunnelConfigSource<'a> {
    repo: wormhole_storage::TunnelConfigRepository<'a>,
}

#[cfg(feature = "storage")]
impl<'a> StorageTunnelConfigSource<'a> {
    pub fn new(repo: wormhole_storage::TunnelConfigRepository<'a>) -> Self {
        Self { repo }
    }
}

#[cfg(feature = "storage")]
impl TunnelConfigSource for StorageTunnelConfigSource<'_> {
    fn list_all(&self) -> Result<Vec<TunnelConfigRow>, TunnelCatalogError> {
        self.repo
            .list_all()
            .map(|rows| rows.into_iter().map(TunnelConfigRow::from).collect())
            .map_err(|e| TunnelCatalogError::Load(e.to_string()))
    }
}

#[cfg(feature = "storage")]
impl From<wormhole_storage::TunnelConfig> for TunnelConfigRow {
    fn from(value: wormhole_storage::TunnelConfig) -> Self {
        Self::config(value.id, value.name, value.kind, value.created_at, value.updated_at)
    }
}

pub fn is_sentinel_id(id: Uuid) -> bool {
    id == INHERIT_TUNNEL_ID || id == NO_TUNNEL_ID
}

/// C# `TunnelConfigsViewModel.KindContains` display names.
pub fn tunnel_kind_display_name(kind: TunnelKind) -> &'static str {
    match kind {
        TunnelKind::WireGuard => "WireGuard",
        TunnelKind::OpenVpn => "OpenVpn",
        TunnelKind::Fortinet => "Fortinet",
        TunnelKind::Watchguard => "Watchguard",
        TunnelKind::Stormshield => "Stormshield",
        TunnelKind::AzureVpn => "Azure VPN",
        TunnelKind::CiscoSecureClient => "Cisco Secure Client AnyConnect",
    }
}

fn name_contains(haystack: &str, query_lower: &str) -> bool {
    if query_lower.is_empty() {
        return false;
    }
    haystack.to_lowercase().contains(query_lower)
}

fn kind_matches_query(kind: TunnelKind, query_lower: &str) -> bool {
    name_contains(tunnel_kind_display_name(kind), query_lower)
}

/// Configs-page filter: name **or** kind display name (C# `MatchesQuery`).
pub fn filter_tunnel_configs_page(
    configs: &[TunnelConfigRow],
    query: &str,
) -> Vec<TunnelConfigRow> {
    let trimmed = query.trim();
    if trimmed.is_empty() {
        return configs.to_vec();
    }
    let query_lower = trimmed.to_lowercase();
    configs
        .iter()
        .filter(|row| {
            !row.is_sentinel()
                && (name_contains(&row.name, &query_lower)
                    || row
                        .kind
                        .is_some_and(|kind| kind_matches_query(kind, &query_lower)))
        })
        .cloned()
        .collect()
}

/// Picker filter: name substring only (C# `FilterTunnelConfigs`).
pub fn filter_tunnel_picker_entries(
    entries: &[TunnelConfigRow],
    query: &str,
) -> Vec<TunnelConfigRow> {
    let trimmed = query.trim();
    if trimmed.is_empty() {
        return entries.to_vec();
    }
    let query_lower = trimmed.to_lowercase();
    entries
        .iter()
        .filter(|row| name_contains(&row.name, &query_lower))
        .cloned()
        .collect()
}

fn stale_tunnel_name(id: Uuid) -> String {
    format!("(missing tunnel {})", id.simple())
}

/// Tunnel configs page VM — list + search + editor selection (metadata only).
///
/// **Load semantics:** successful [`load_from`](Self::load_from) **replaces** the cached
/// snapshot (does not append). On `Err`, prior configs / search / selection are left
/// untouched (**last-good**, matching C# `LoadAsync` catch). No debounce (host owns it).
#[derive(Clone)]
pub struct TunnelConfigsVm {
    configs: Vec<TunnelConfigRow>,
    search_text: String,
    selected_id: Option<Uuid>,
    loaded: bool,
}

impl Default for TunnelConfigsVm {
    fn default() -> Self {
        Self::new()
    }
}

impl TunnelConfigsVm {
    pub fn new() -> Self {
        Self {
            configs: Vec::new(),
            search_text: String::new(),
            selected_id: None,
            loaded: false,
        }
    }

    pub fn from_configs(configs: impl IntoIterator<Item = TunnelConfigRow>) -> Self {
        Self {
            configs: configs.into_iter().collect(),
            search_text: String::new(),
            selected_id: None,
            loaded: true,
        }
    }

    pub fn load_from<S: TunnelConfigSource + ?Sized>(
        &mut self,
        source: &S,
    ) -> Result<(), TunnelCatalogError> {
        self.configs = source.list_all()?;
        self.loaded = true;
        if let Some(id) = self.selected_id {
            if !self.configs.iter().any(|c| c.id == id) {
                self.selected_id = None;
            }
        }
        Ok(())
    }

    pub fn is_loaded(&self) -> bool {
        self.loaded
    }

    pub fn set_search_text(&mut self, text: impl Into<String>) {
        self.search_text = text.into();
    }

    pub fn search_text(&self) -> &str {
        &self.search_text
    }

    pub fn configs(&self) -> &[TunnelConfigRow] {
        &self.configs
    }

    pub fn filtered(&self) -> Vec<TunnelConfigRow> {
        filter_tunnel_configs_page(&self.configs, &self.search_text)
    }

    pub fn is_empty(&self) -> bool {
        self.configs.is_empty()
    }

    pub fn has_matches(&self) -> bool {
        !self.filtered().is_empty()
    }

    pub fn has_no_matches(&self) -> bool {
        !self.is_empty() && !self.has_matches()
    }

    pub fn select_config(&mut self, id: Option<Uuid>) {
        self.selected_id = id.filter(|id| self.configs.iter().any(|c| c.id == *id));
    }

    pub fn selected_id(&self) -> Option<Uuid> {
        self.selected_id
    }

    pub fn selected_config(&self) -> Option<&TunnelConfigRow> {
        let id = self.selected_id?;
        self.configs.iter().find(|c| c.id == id)
    }
}

impl fmt::Debug for TunnelConfigsVm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TunnelConfigsVm")
            .field("config_count", &self.configs.len())
            .field("search_len", &self.search_text.len())
            .field("selected_id", &self.selected_id)
            .field("loaded", &self.loaded)
            .finish()
    }
}

/// Tri-state tunnel picker VM (connection / folder editor).
///
/// Seeds inherit + no-tunnel sentinels up front. [`load_from`](Self::load_from) rebuilds
/// the available list from a [`TunnelConfigSource`]. Selection reads/writes [`TunnelUiState`].
#[derive(Clone)]
pub struct TunnelPickerVm {
    ui: TunnelUiState,
    inherit_label: String,
    available: Vec<TunnelConfigRow>,
    by_id: HashMap<Uuid, TunnelConfigRow>,
}

impl TunnelPickerVm {
    pub fn new(inherit_label: impl Into<String>) -> Self {
        let inherit_label = inherit_label.into();
        let inherit = TunnelConfigRow::sentinel(INHERIT_TUNNEL_ID, inherit_label.clone());
        let no_tunnel = TunnelConfigRow::sentinel(NO_TUNNEL_ID, "(No tunnel)");
        let mut by_id = HashMap::new();
        by_id.insert(inherit.id, inherit.clone());
        by_id.insert(no_tunnel.id, no_tunnel.clone());
        Self {
            ui: TunnelUiState::default(),
            inherit_label,
            available: vec![inherit, no_tunnel],
            by_id,
        }
    }

    pub fn inherit_row(&self) -> &TunnelConfigRow {
        self.by_id
            .get(&INHERIT_TUNNEL_ID)
            .expect("inherit sentinel seeded")
    }

    pub fn no_tunnel_row(&self) -> &TunnelConfigRow {
        self.by_id
            .get(&NO_TUNNEL_ID)
            .expect("no-tunnel sentinel seeded")
    }

    pub fn allow_inheritance(&self) -> bool {
        self.ui.allow_inheritance
    }

    pub fn configure_inheritance(&mut self, allow: bool) {
        if self.ui.allow_inheritance == allow {
            return;
        }
        self.ui.allow_inheritance = allow;
        if !allow && self.ui.enabled.is_none() {
            self.ui.set_selection(TunnelUiSelection::NoTunnel);
        }
        self.rebuild_available_preserving_stale();
    }

    pub fn load_from<S: TunnelConfigSource + ?Sized>(
        &mut self,
        source: &S,
    ) -> Result<(), TunnelCatalogError> {
        let configs = source.list_all()?;
        self.replace_available_from_repo(configs);
        self.append_stale_selection(self.ui.config_id);
        Ok(())
    }

    pub fn load_from_node(
        &mut self,
        tunnel_enabled: Option<bool>,
        tunnel_config_id: Option<Uuid>,
    ) {
        self.append_stale_selection(tunnel_config_id);
        self.ui
            .load_from_node(tunnel_enabled, tunnel_config_id);
    }

    pub fn ui_state(&self) -> &TunnelUiState {
        &self.ui
    }

    pub fn ui_state_mut(&mut self) -> &mut TunnelUiState {
        &mut self.ui
    }

    pub fn available(&self) -> &[TunnelConfigRow] {
        &self.available
    }

    pub fn selected_tunnel(&self) -> Option<&TunnelConfigRow> {
        match self.ui.selection() {
            TunnelUiSelection::NoTunnel => Some(self.no_tunnel_row()),
            TunnelUiSelection::Inherit => Some(self.inherit_row()),
            TunnelUiSelection::Config(id) => self.by_id.get(&id),
            TunnelUiSelection::EnabledNoConfig => None,
        }
    }

    pub fn set_selected_tunnel(&mut self, row: Option<&TunnelConfigRow>) {
        let selection = match row {
            None => {
                if self.ui.allow_inheritance {
                    TunnelUiSelection::Inherit
                } else {
                    TunnelUiSelection::NoTunnel
                }
            }
            Some(r) if r.id == INHERIT_TUNNEL_ID => TunnelUiSelection::Inherit,
            Some(r) if r.id == NO_TUNNEL_ID => TunnelUiSelection::NoTunnel,
            Some(r) => TunnelUiSelection::Config(r.id),
        };
        self.ui.set_selection(selection);
    }

    pub fn filter_tunnel_configs(&self, query: &str) -> Vec<TunnelConfigRow> {
        filter_tunnel_picker_entries(&self.available, query)
    }

    /// Exact name (case-insensitive), else unique non-sentinel substring match.
    pub fn resolve_tunnel_for_commit(&self, text: &str) -> Option<&TunnelConfigRow> {
        let trimmed = text.trim();
        if trimmed.is_empty() {
            return None;
        }
        for row in &self.available {
            if row.name.eq_ignore_ascii_case(trimmed) {
                return Some(row);
            }
        }
        let mut single: Option<&TunnelConfigRow> = None;
        let query_lower = trimmed.to_lowercase();
        for row in &self.available {
            if row.is_sentinel() {
                continue;
            }
            if !name_contains(&row.name, &query_lower) {
                continue;
            }
            if single.is_some() {
                return None;
            }
            single = Some(row);
        }
        single
    }

    pub fn write_node_fields(&self) -> (Option<bool>, Option<Uuid>) {
        self.ui.to_node_fields()
    }

    fn replace_available_from_repo(&mut self, configs: Vec<TunnelConfigRow>) {
        let inherit = TunnelConfigRow::sentinel(INHERIT_TUNNEL_ID, self.inherit_label.clone());
        let no_tunnel = TunnelConfigRow::sentinel(NO_TUNNEL_ID, "(No tunnel)");
        let mut available = Vec::with_capacity(configs.len() + 2);
        if self.ui.allow_inheritance {
            available.push(inherit.clone());
        }
        available.push(no_tunnel.clone());
        available.extend(configs);
        self.by_id.clear();
        for row in &available {
            self.by_id.insert(row.id, row.clone());
        }
        self.available = available;
    }

    fn rebuild_available_preserving_stale(&mut self) {
        let configs: Vec<TunnelConfigRow> = self
            .available
            .iter()
            .filter(|r| !r.is_sentinel() && r.kind.is_some())
            .cloned()
            .collect();
        let stale: Vec<TunnelConfigRow> = self
            .available
            .iter()
            .filter(|r| !r.is_sentinel() && r.kind.is_none())
            .cloned()
            .collect();
        self.replace_available_from_repo(configs);
        for row in stale {
            self.insert_stale_row(row);
        }
    }

    fn append_stale_selection(&mut self, id: Option<Uuid>) {
        let Some(id) = id else { return };
        if is_sentinel_id(id) || self.by_id.contains_key(&id) {
            return;
        }
        let stale = TunnelConfigRow::sentinel(id, stale_tunnel_name(id));
        self.insert_stale_row(stale);
    }

    fn insert_stale_row(&mut self, row: TunnelConfigRow) {
        if self.by_id.contains_key(&row.id) {
            return;
        }
        self.by_id.insert(row.id, row.clone());
        self.available.push(row);
    }
}

impl fmt::Debug for TunnelPickerVm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TunnelPickerVm")
            .field("available_count", &self.available.len())
            .field("allow_inheritance", &self.ui.allow_inheritance)
            .field("selection", &self.ui.selection())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn ts() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap()
    }

    fn config_row(name: &str, kind: TunnelKind) -> TunnelConfigRow {
        TunnelConfigRow::config(Uuid::new_v4(), name, kind, ts(), ts())
    }

    #[test]
    fn configs_page_filter_matches_name_or_kind_display() {
        let wg = config_row("corp-vpn", TunnelKind::WireGuard);
        let az = config_row("remote", TunnelKind::AzureVpn);
        let rows = vec![wg.clone(), az.clone()];
        assert_eq!(filter_tunnel_configs_page(&rows, ""), rows);
        assert_eq!(filter_tunnel_configs_page(&rows, "CORP"), vec![wg]);
        assert_eq!(filter_tunnel_configs_page(&rows, "azure vpn"), vec![az]);
        assert!(filter_tunnel_configs_page(&rows, "missing").is_empty());
    }

    #[test]
    fn picker_filter_name_only_empty_returns_all_including_sentinels() {
        let mut picker = TunnelPickerVm::new("(Inherit from folder)");
        let wg = config_row("Office", TunnelKind::WireGuard);
        let fake = FakeTunnelConfigList::with_configs([wg.clone()]);
        picker.load_from(&fake).unwrap();
        assert_eq!(picker.available().len(), 3);
        let filtered = picker.filter_tunnel_configs("off");
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].name, "Office");
        assert_eq!(
            picker.filter_tunnel_configs("").len(),
            picker.available().len()
        );
        assert!(picker.filter_tunnel_configs("wireguard").is_empty());
    }

    #[test]
    fn resolve_tunnel_for_commit_exact_then_unique_substring() {
        let prod = config_row("prod", TunnelKind::WireGuard);
        let backup = config_row("prod-backup", TunnelKind::OpenVpn);
        let mut picker = TunnelPickerVm::new("(Inherit from folder)");
        picker
            .load_from(&FakeTunnelConfigList::with_configs([prod.clone(), backup.clone()]))
            .unwrap();
        assert_eq!(picker.resolve_tunnel_for_commit("PROD").unwrap().id, prod.id);
        assert_eq!(
            picker.resolve_tunnel_for_commit("backup").unwrap().id,
            backup.id
        );
        assert!(picker.resolve_tunnel_for_commit("pro").is_none());
        assert!(picker.resolve_tunnel_for_commit("missing").is_none());
        assert!(picker.resolve_tunnel_for_commit("").is_none());
    }

    #[test]
    fn picker_sentinel_selection_round_trip() {
        let mut picker = TunnelPickerVm::new("(Inherit from folder)");
        let inherit = picker.inherit_row().clone();
        let no_tunnel = picker.no_tunnel_row().clone();
        picker.set_selected_tunnel(Some(&inherit));
        assert_eq!(picker.ui_state().selection(), TunnelUiSelection::Inherit);
        assert!(picker.ui_state().enabled.is_none());
        assert!(picker.ui_state().config_id.is_none());

        picker.set_selected_tunnel(Some(&no_tunnel));
        assert_eq!(picker.ui_state().selection(), TunnelUiSelection::NoTunnel);
        assert_eq!(picker.ui_state().enabled, Some(false));
    }

    #[test]
    fn picker_stale_id_appends_placeholder_and_resolves_selection() {
        let deleted = Uuid::new_v4();
        let mut picker = TunnelPickerVm::new("(Inherit from folder)");
        picker.load_from(&FakeTunnelConfigList::new()).unwrap();
        picker.load_from_node(Some(true), Some(deleted));
        assert!(picker.available().iter().any(|r| r.id == deleted));
        assert_eq!(picker.selected_tunnel().unwrap().id, deleted);
        let (enabled, config_id) = picker.write_node_fields();
        assert_eq!(enabled, Some(true));
        assert_eq!(config_id, Some(deleted));
    }

    #[test]
    fn picker_configure_inheritance_coerces_inherit_to_no_tunnel() {
        let mut picker = TunnelPickerVm::new("(Inherit from folder)");
        let inherit = picker.inherit_row().clone();
        picker.set_selected_tunnel(Some(&inherit));
        picker.configure_inheritance(false);
        assert!(!picker.allow_inheritance());
        assert_eq!(picker.ui_state().selection(), TunnelUiSelection::NoTunnel);
        assert!(!picker.available().iter().any(|r| r.id == INHERIT_TUNNEL_ID));
    }

    #[test]
    fn configs_vm_load_replace_and_last_good_on_err() {
        let a = config_row("alpha", TunnelKind::WireGuard);
        let mut vm = TunnelConfigsVm::from_configs([a.clone()]);
        vm.set_search_text("alpha");
        vm.select_config(Some(a.id));
        let failing = FakeTunnelConfigList::failing("db down");
        let err = vm.load_from(&failing).unwrap_err();
        assert_eq!(err, TunnelCatalogError::Load("db down".into()));
        assert_eq!(vm.configs(), &[a.clone()]);
        assert_eq!(vm.search_text(), "alpha");
        assert_eq!(vm.selected_id(), Some(a.id));

        let b = config_row("beta", TunnelKind::OpenVpn);
        vm.load_from(&FakeTunnelConfigList::with_configs([b.clone()]))
            .unwrap();
        assert_eq!(vm.configs().len(), 1);
        assert_eq!(vm.configs()[0].name, "beta");
        assert!(vm.selected_id().is_none());
    }

    #[test]
    fn configs_vm_empty_and_no_matches_flags() {
        let mut vm = TunnelConfigsVm::new();
        vm.load_from(&FakeTunnelConfigList::new()).unwrap();
        assert!(vm.is_empty());
        assert!(!vm.has_matches());
        assert!(!vm.has_no_matches());

        vm.load_from(&FakeTunnelConfigList::with_configs([config_row(
            "vpn",
            TunnelKind::WireGuard,
        )]))
        .unwrap();
        vm.set_search_text("nope");
        assert!(!vm.is_empty());
        assert!(!vm.has_matches());
        assert!(vm.has_no_matches());
    }

    #[test]
    fn fake_set_configs_clears_fail_flag() {
        let fake = FakeTunnelConfigList::failing("boom");
        assert!(fake.list_all().is_err());
        fake.set_configs([config_row("x", TunnelKind::WireGuard)]);
        assert_eq!(fake.list_all().unwrap().len(), 1);
    }

    #[test]
    fn debug_omits_secret_shaped_fields() {
        let row = config_row("vpn", TunnelKind::Fortinet);
        let dbg = format!("{row:?}");
        assert!(dbg.contains("Fortinet"));
        assert!(!dbg.to_lowercase().contains("password"));
        assert!(!dbg.to_lowercase().contains("secret"));
        assert!(!dbg.to_lowercase().contains("dpapi"));

        let mut vm = TunnelConfigsVm::new();
        vm.set_search_text("needle-not-in-debug");
        let vm_dbg = format!("{vm:?}");
        assert!(vm_dbg.contains("search_len"));
        assert!(!vm_dbg.contains("needle-not-in-debug"));

        let picker_dbg = format!("{:?}", TunnelPickerVm::new("inherit"));
        assert!(picker_dbg.contains("available_count"));
        assert!(!picker_dbg.contains("password"));
    }

    #[test]
    fn empty_query_lower_does_not_match_via_contains_empty() {
        let row = config_row("anything", TunnelKind::WireGuard);
        assert!(!name_contains(&row.name, ""));
    }

    #[test]
    fn picker_enabled_false_trumps_vestigial_config_id_for_display() {
        let id = Uuid::new_v4();
        let mut picker = TunnelPickerVm::new("(Inherit from folder)");
        picker.load_from(&FakeTunnelConfigList::new()).unwrap();
        picker.load_from_node(Some(false), Some(id));
        assert_eq!(picker.selected_tunnel().unwrap().id, NO_TUNNEL_ID);
        assert_eq!(picker.ui_state().config_id, None);
    }

    #[test]
    fn configs_vm_select_config_rejects_unknown_id() {
        let mut vm = TunnelConfigsVm::from_configs([config_row("vpn", TunnelKind::WireGuard)]);
        vm.select_config(Some(Uuid::new_v4()));
        assert!(vm.selected_id().is_none());
    }

    #[cfg(feature = "storage")]
    #[test]
    fn storage_source_lists_metadata_only() {
        use tempfile::tempdir;
        use wormhole_storage::{MigrationRunner, SqliteConnectionFactory, TunnelConfigRepository};

        let dir = tempdir().unwrap();
        let factory = SqliteConnectionFactory::new(dir.path().join("wormhole.db"));
        MigrationRunner::embedded().run(&factory).unwrap();
        let repo = TunnelConfigRepository::new(&factory);
        let id = Uuid::new_v4();
        repo.insert(id, "lab-vpn", TunnelKind::WireGuard).unwrap();
        let source = StorageTunnelConfigSource::new(repo);
        let rows = source.list_all().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].name, "lab-vpn");
        assert_eq!(rows[0].kind, Some(TunnelKind::WireGuard));
        let dbg = format!("{:?}", rows[0]);
        assert!(!dbg.to_lowercase().contains("password"));
        assert!(!dbg.to_lowercase().contains("secret"));
    }
}
