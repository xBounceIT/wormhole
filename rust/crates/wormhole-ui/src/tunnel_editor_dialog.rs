//! Tunnel editor dialog Fake VM glue (C# `TunnelDialog` / `TunnelConfigsViewModel` save spirit).
//!
//! Create / edit tunnel config **metadata** via [`FakeTunnelConfigList`] (or optional
//! [`StorageTunnelConfigSource`] behind `--features storage`) and optional DPAPI payload
//! write via [`FakeTunnelPayloadStore`] (`--features secrets`). **No GPUI**; payload bytes
//! never appear in [`Debug`] / log surfaces. Fail-closed on empty name / missing kind.

use std::fmt;

use chrono::{DateTime, Utc};
use thiserror::Error;
use uuid::Uuid;
use wormhole_domain::TunnelKind;

use crate::tunnel_configs_ui::{
    tunnel_name_exists, FakeTunnelConfigList, TunnelCatalogError, TunnelConfigRow,
    TunnelConfigSource,
};

#[cfg(feature = "secrets")]
use wormhole_secrets_win::TunnelPayloadStore;

/// Dialog / save errors — never carry secret payloads.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum TunnelEditorDialogError {
    #[error("tunnel name is required")]
    NameRequired,
    #[error("tunnel kind is required")]
    KindRequired,
    #[error("tunnel name already in use")]
    NameInUse,
    #[error("tunnel config not found")]
    NotFound,
    #[error("invalid tunnel config row")]
    InvalidRow,
    #[error("catalog error: {0}")]
    Catalog(String),
    #[cfg(feature = "secrets")]
    #[error("payload store error: {0}")]
    PayloadStore(String),
    #[cfg(feature = "storage")]
    #[error("storage error: {0}")]
    Storage(String),
}

impl From<TunnelCatalogError> for TunnelEditorDialogError {
    fn from(value: TunnelCatalogError) -> Self {
        Self::Catalog(value.to_string())
    }
}

/// Editor draft — payload stays out of list rows and [`Debug`].
#[derive(Clone)]
pub struct TunnelSaveDraft {
    pub id: Option<Uuid>,
    pub name: String,
    pub kind: Option<TunnelKind>,
    payload: Option<Vec<u8>>,
}

impl TunnelSaveDraft {
    pub fn new(name: impl Into<String>, kind: TunnelKind) -> Self {
        Self {
            id: None,
            name: name.into(),
            kind: Some(kind),
            payload: None,
        }
    }

    pub fn with_payload(mut self, payload: impl Into<Vec<u8>>) -> Self {
        self.payload = Some(payload.into());
        self
    }

    pub fn has_payload(&self) -> bool {
        self.payload.is_some()
    }

    pub fn payload_len(&self) -> usize {
        self.payload.as_ref().map(|b| b.len()).unwrap_or(0)
    }

    pub fn set_payload(&mut self, payload: impl Into<Vec<u8>>) {
        self.payload = Some(payload.into());
    }

    pub fn clear_payload(&mut self) {
        self.payload = None;
    }
}

impl fmt::Debug for TunnelSaveDraft {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TunnelSaveDraft")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("kind", &self.kind)
            .field("payload_len", &self.payload_len())
            .finish()
    }
}

/// In-memory lab harness composing metadata + optional payload Fakes.
pub struct FakeTunnelEditorLab {
    pub configs: FakeTunnelConfigList,
    #[cfg(feature = "secrets")]
    pub payloads: wormhole_secrets_win::FakeTunnelPayloadStore,
}

impl Default for FakeTunnelEditorLab {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for FakeTunnelEditorLab {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut dbg = f.debug_struct("FakeTunnelEditorLab");
        dbg.field("configs", &self.configs);
        #[cfg(feature = "secrets")]
        dbg.field("payloads", &self.payloads);
        dbg.finish()
    }
}

impl FakeTunnelEditorLab {
    pub fn new() -> Self {
        Self {
            configs: FakeTunnelConfigList::new(),
            #[cfg(feature = "secrets")]
            payloads: wormhole_secrets_win::FakeTunnelPayloadStore::new(),
        }
    }

    pub fn with_config(row: TunnelConfigRow, payload: Option<Vec<u8>>) -> Self {
        let lab = Self::new();
        lab.configs.insert_row(row.clone()).expect("seed config");
        #[cfg(feature = "secrets")]
        if let Some(bytes) = payload {
            lab.payloads
                .store(&row.id, &bytes)
                .expect("seed payload");
        }
        let _ = payload;
        lab
    }
}

/// Tunnel editor dialog VM — metadata fields + optional payload replace on save.
///
/// Per-kind required-field validation (WireGuard keys, Fortinet host, etc.) stays in the
/// host / future provider draft builders; this VM fail-closes on **name** and **kind** only
/// (C# dialog always requires both before save).
#[derive(Clone)]
pub struct TunnelEditorDialogVm {
    editing_id: Option<Uuid>,
    original_updated_at: Option<DateTime<Utc>>,
    name: String,
    kind: Option<TunnelKind>,
    payload_replace: Option<Vec<u8>>,
    had_payload_on_open: bool,
}

impl Default for TunnelEditorDialogVm {
    fn default() -> Self {
        Self::new()
    }
}

impl TunnelEditorDialogVm {
    pub fn new() -> Self {
        Self {
            editing_id: None,
            original_updated_at: None,
            name: String::new(),
            kind: None,
            payload_replace: None,
            had_payload_on_open: false,
        }
    }

    pub fn is_edit(&self) -> bool {
        self.editing_id.is_some()
    }

    pub fn editing_id(&self) -> Option<Uuid> {
        self.editing_id
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn kind(&self) -> Option<TunnelKind> {
        self.kind
    }

    pub fn set_name(&mut self, name: impl Into<String>) {
        self.name = name.into();
    }

    pub fn set_kind(&mut self, kind: TunnelKind) {
        self.kind = Some(kind);
    }

    pub fn clear_kind(&mut self) {
        self.kind = None;
    }

    pub fn set_payload_replace(&mut self, payload: impl Into<Vec<u8>>) {
        self.payload_replace = Some(payload.into());
    }

    pub fn clear_payload_replace(&mut self) {
        self.payload_replace = None;
    }

    pub fn payload_replace_len(&self) -> usize {
        self.payload_replace.as_ref().map(|b| b.len()).unwrap_or(0)
    }

    pub fn prepare_new(&mut self) {
        *self = Self::new();
    }

    pub fn prepare_edit(&mut self, row: &TunnelConfigRow) -> Result<(), TunnelEditorDialogError> {
        if row.is_sentinel() {
            return Err(TunnelEditorDialogError::InvalidRow);
        }
        let Some(kind) = row.kind else {
            return Err(TunnelEditorDialogError::InvalidRow);
        };
        self.editing_id = Some(row.id);
        self.original_updated_at = row.updated_at;
        self.name = row.name.clone();
        self.kind = Some(kind);
        self.payload_replace = None;
        self.had_payload_on_open = false;
        Ok(())
    }

    #[cfg(feature = "secrets")]
    pub fn prepare_edit_with_payload(
        &mut self,
        row: &TunnelConfigRow,
        lab: &FakeTunnelEditorLab,
    ) -> Result<(), TunnelEditorDialogError> {
        self.prepare_edit(row)?;
        self.had_payload_on_open = lab
            .payloads
            .read(&row.id)
            .map_err(|e| TunnelEditorDialogError::PayloadStore(e.to_string()))?
            .is_some();
        Ok(())
    }

    pub fn validate(&self) -> Result<(), TunnelEditorDialogError> {
        if self.name.trim().is_empty() {
            return Err(TunnelEditorDialogError::NameRequired);
        }
        if self.kind.is_none() {
            return Err(TunnelEditorDialogError::KindRequired);
        }
        Ok(())
    }

    pub fn is_valid(&self) -> bool {
        self.validate().is_ok()
    }

    pub fn build_draft(&self) -> Result<TunnelSaveDraft, TunnelEditorDialogError> {
        self.validate()?;
        Ok(TunnelSaveDraft {
            id: self.editing_id,
            name: self.name.trim().to_owned(),
            kind: self.kind,
            payload: self.payload_replace.clone(),
        })
    }

    pub fn save_to_lab(&self, lab: &FakeTunnelEditorLab) -> Result<TunnelConfigRow, TunnelEditorDialogError> {
        let draft = self.build_draft()?;
        let existing = lab.configs.list_all()?;
        if tunnel_name_exists(&existing, &draft.name, draft.id) {
            return Err(TunnelEditorDialogError::NameInUse);
        }
        let kind = draft.kind.ok_or(TunnelEditorDialogError::KindRequired)?;
        let now = Utc::now();

        let row = if let Some(id) = draft.id {
            let created_at = existing
                .iter()
                .find(|r| r.id == id)
                .and_then(|r| r.created_at)
                .ok_or(TunnelEditorDialogError::NotFound)?;
            let stamp = self.original_updated_at.unwrap_or(now);
            let interim = TunnelConfigRow::config(id, draft.name.clone(), kind, created_at, stamp);
            lab.configs.update_row(interim)?;
            #[cfg(feature = "secrets")]
            if let Some(payload) = &draft.payload {
                lab.payloads
                    .store(&id, payload)
                    .map_err(|e| TunnelEditorDialogError::PayloadStore(e.to_string()))?;
            }
            let bumped = TunnelConfigRow::config(id, draft.name, kind, created_at, now);
            lab.configs.update_row(bumped.clone())?;
            bumped
        } else {
            let id = Uuid::new_v4();
            let row = TunnelConfigRow::config(id, draft.name, kind, now, now);
            lab.configs.insert_row(row.clone())?;
            #[cfg(feature = "secrets")]
            if let Some(payload) = &draft.payload {
                lab.payloads
                    .store(&id, payload)
                    .map_err(|e| TunnelEditorDialogError::PayloadStore(e.to_string()))?;
            }
            row
        };

        Ok(row)
    }
}

impl fmt::Debug for TunnelEditorDialogVm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TunnelEditorDialogVm")
            .field("editing_id", &self.editing_id)
            .field("name_len", &self.name.len())
            .field("kind", &self.kind)
            .field("payload_replace_len", &self.payload_replace_len())
            .field("had_payload_on_open", &self.had_payload_on_open)
            .finish()
    }
}

#[cfg(feature = "storage")]
pub fn save_tunnel_config(
    repo: &wormhole_storage::TunnelConfigRepository<'_>,
    draft: TunnelSaveDraft,
    existing_names: &[TunnelConfigRow],
) -> Result<TunnelConfigRow, TunnelEditorDialogError> {
    #[cfg(feature = "secrets")]
    {
        return save_tunnel_config_with_payload(repo, None, draft, existing_names);
    }
    #[cfg(not(feature = "secrets"))]
    {
        if draft.name.trim().is_empty() {
            return Err(TunnelEditorDialogError::NameRequired);
        }
        let kind = draft.kind.ok_or(TunnelEditorDialogError::KindRequired)?;
        if tunnel_name_exists(existing_names, &draft.name, draft.id) {
            return Err(TunnelEditorDialogError::NameInUse);
        }
        if let Some(id) = draft.id {
            let mut config = repo
                .get_by_id(id)
                .map_err(|e| TunnelEditorDialogError::Storage(e.to_string()))?
                .ok_or(TunnelEditorDialogError::NotFound)?;
            let old_stamp = config.updated_at;
            config.name = draft.name;
            config.kind = kind;
            config.updated_at = old_stamp;
            repo.update(&config)
                .map_err(|e| TunnelEditorDialogError::Storage(e.to_string()))?;
            config.updated_at = Utc::now();
            repo.update(&config)
                .map_err(|e| TunnelEditorDialogError::Storage(e.to_string()))?;
            Ok(TunnelConfigRow::from(config))
        } else {
            let id = Uuid::new_v4();
            let config = repo
                .insert(id, &draft.name, kind)
                .map_err(|e| TunnelEditorDialogError::Storage(e.to_string()))?;
            Ok(TunnelConfigRow::from(config))
        }
    }
}

#[cfg(all(feature = "storage", feature = "secrets"))]
pub fn save_tunnel_config_with_payload(
    repo: &wormhole_storage::TunnelConfigRepository<'_>,
    payloads: Option<&dyn TunnelPayloadStore>,
    draft: TunnelSaveDraft,
    existing_names: &[TunnelConfigRow],
) -> Result<TunnelConfigRow, TunnelEditorDialogError> {
    if draft.name.trim().is_empty() {
        return Err(TunnelEditorDialogError::NameRequired);
    }
    let kind = draft.kind.ok_or(TunnelEditorDialogError::KindRequired)?;
    if tunnel_name_exists(existing_names, &draft.name, draft.id) {
        return Err(TunnelEditorDialogError::NameInUse);
    }

    if let Some(id) = draft.id {
        let mut config = repo
            .get_by_id(id)
            .map_err(|e| TunnelEditorDialogError::Storage(e.to_string()))?
            .ok_or(TunnelEditorDialogError::NotFound)?;
        let old_stamp = config.updated_at;
        config.name = draft.name.clone();
        config.kind = kind;
        config.updated_at = old_stamp;
        repo.update(&config)
            .map_err(|e| TunnelEditorDialogError::Storage(e.to_string()))?;
        if let (Some(store), Some(payload)) = (payloads, &draft.payload) {
            store
                .store(&id, payload)
                .map_err(|e| TunnelEditorDialogError::PayloadStore(e.to_string()))?;
        }
        config.updated_at = Utc::now();
        repo.update(&config)
            .map_err(|e| TunnelEditorDialogError::Storage(e.to_string()))?;
        Ok(TunnelConfigRow::from(config))
    } else {
        let id = Uuid::new_v4();
        let config = repo
            .insert(id, &draft.name, kind)
            .map_err(|e| TunnelEditorDialogError::Storage(e.to_string()))?;
        if let (Some(store), Some(payload)) = (payloads, &draft.payload) {
            store
                .store(&id, payload)
                .map_err(|e| TunnelEditorDialogError::PayloadStore(e.to_string()))?;
        }
        Ok(TunnelConfigRow::from(config))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn ts() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap()
    }

    fn row(name: &str, kind: TunnelKind) -> TunnelConfigRow {
        TunnelConfigRow::config(Uuid::new_v4(), name, kind, ts(), ts())
    }

    #[test]
    fn validate_rejects_empty_name_and_missing_kind() {
        let mut vm = TunnelEditorDialogVm::new();
        assert_eq!(vm.validate(), Err(TunnelEditorDialogError::NameRequired));
        vm.set_name("corp");
        assert_eq!(vm.validate(), Err(TunnelEditorDialogError::KindRequired));
        vm.set_kind(TunnelKind::WireGuard);
        assert!(vm.validate().is_ok());
        vm.set_name("   ");
        assert_eq!(vm.validate(), Err(TunnelEditorDialogError::NameRequired));
    }

    #[test]
    fn debug_omits_payload_bytes() {
        let draft = TunnelSaveDraft::new("vpn", TunnelKind::OpenVpn).with_payload(vec![1, 2, 3]);
        let debug = format!("{draft:?}");
        assert!(debug.contains("payload_len"));
        assert!(!debug.contains("[1, 2, 3]"));
        let mut vm = TunnelEditorDialogVm::new();
        vm.set_payload_replace(vec![9, 9, 9]);
        let vm_debug = format!("{vm:?}");
        assert!(vm_debug.contains("payload_replace_len"));
        assert!(!vm_debug.contains("9, 9, 9"));
    }

    #[test]
    fn save_new_metadata_only() {
        let lab = FakeTunnelEditorLab::new();
        let mut vm = TunnelEditorDialogVm::new();
        vm.set_name("corp-vpn");
        vm.set_kind(TunnelKind::WireGuard);
        let saved = vm.save_to_lab(&lab).unwrap();
        assert_eq!(saved.name, "corp-vpn");
        assert_eq!(saved.kind, Some(TunnelKind::WireGuard));
        assert_eq!(lab.configs.list_all().unwrap().len(), 1);
    }

    #[test]
    fn save_rejects_duplicate_name() {
        let existing = row("Alpha", TunnelKind::WireGuard);
        let lab = FakeTunnelEditorLab::with_config(existing, None);
        let mut vm = TunnelEditorDialogVm::new();
        vm.set_name("alpha");
        vm.set_kind(TunnelKind::OpenVpn);
        assert_eq!(vm.save_to_lab(&lab), Err(TunnelEditorDialogError::NameInUse));
    }

    #[test]
    fn edit_bumps_updated_at_after_metadata_write() {
        let original = row("corp", TunnelKind::WireGuard);
        let id = original.id;
        let lab = FakeTunnelEditorLab::with_config(original, None);
        let mut vm = TunnelEditorDialogVm::new();
        vm.prepare_edit(&lab.configs.get_by_id(id).unwrap().unwrap())
            .unwrap();
        vm.set_name("corp-renamed");
        let saved = vm.save_to_lab(&lab).unwrap();
        assert_eq!(saved.name, "corp-renamed");
        assert!(saved.updated_at.unwrap() > ts());
    }

    #[test]
    fn prepare_edit_rejects_sentinel() {
        let mut vm = TunnelEditorDialogVm::new();
        let sentinel = TunnelConfigRow::sentinel(
            crate::tunnel_configs_ui::INHERIT_TUNNEL_ID,
            "(Inherit)",
        );
        assert_eq!(
            vm.prepare_edit(&sentinel),
            Err(TunnelEditorDialogError::InvalidRow)
        );
    }

    #[cfg(feature = "secrets")]
    #[test]
    fn save_writes_optional_payload() {
        let lab = FakeTunnelEditorLab::new();
        let mut vm = TunnelEditorDialogVm::new();
        vm.set_name("secret-vpn");
        vm.set_kind(TunnelKind::Fortinet);
        vm.set_payload_replace(b"fortinet-payload".to_vec());
        let saved = vm.save_to_lab(&lab).unwrap();
        let payload = lab.payloads.read(&saved.id).unwrap().unwrap();
        assert_eq!(payload, b"fortinet-payload");
    }

    #[cfg(feature = "secrets")]
    #[test]
    fn edit_payload_replace_only_when_set() {
        let original = row("corp", TunnelKind::WireGuard);
        let id = original.id;
        let lab = FakeTunnelEditorLab::with_config(original, Some(b"old".to_vec()));
        let mut vm = TunnelEditorDialogVm::new();
        vm.prepare_edit_with_payload(
            &lab.configs.get_by_id(id).unwrap().unwrap(),
            &lab,
        )
        .unwrap();
        vm.set_payload_replace(b"new".to_vec());
        vm.save_to_lab(&lab).unwrap();
        assert_eq!(lab.payloads.read(&id).unwrap().unwrap(), b"new");

        let mut vm2 = TunnelEditorDialogVm::new();
        vm2.prepare_edit_with_payload(
            &lab.configs.get_by_id(id).unwrap().unwrap(),
            &lab,
        )
        .unwrap();
        vm2.set_name("corp-2");
        vm2.save_to_lab(&lab).unwrap();
        assert_eq!(lab.payloads.read(&id).unwrap().unwrap(), b"new");
    }

    #[cfg(feature = "storage")]
    #[test]
    fn storage_save_metadata_round_trip() {
        use wormhole_storage::{MigrationRunner, SqliteConnectionFactory, TunnelConfigRepository};

        let dir = tempfile::tempdir().unwrap();
        let factory = SqliteConnectionFactory::new(dir.path().join("wormhole.db"));
        MigrationRunner::embedded().run(&factory).unwrap();
        let repo = TunnelConfigRepository::new(&factory);

        let draft = TunnelSaveDraft::new("lab-vpn", TunnelKind::OpenVpn);
        let saved = save_tunnel_config(&repo, draft, &[]).unwrap();
        assert_eq!(saved.name, "lab-vpn");
        assert_eq!(saved.kind, Some(TunnelKind::OpenVpn));
    }

    #[cfg(all(feature = "storage", feature = "secrets"))]
    #[test]
    fn storage_save_with_payload_two_phase_updated_at() {
        use wormhole_secrets_win::FakeTunnelPayloadStore;
        use wormhole_storage::{MigrationRunner, SqliteConnectionFactory, TunnelConfigRepository};

        let dir = tempfile::tempdir().unwrap();
        let factory = SqliteConnectionFactory::new(dir.path().join("wormhole.db"));
        MigrationRunner::embedded().run(&factory).unwrap();
        let repo = TunnelConfigRepository::new(&factory);
        let payloads = FakeTunnelPayloadStore::new();

        let created = save_tunnel_config_with_payload(
            &repo,
            Some(&payloads),
            TunnelSaveDraft::new("wg", TunnelKind::WireGuard).with_payload(b"v1"),
            &[],
        )
        .unwrap();
        let first_stamp = created.updated_at.unwrap();

        let edited = save_tunnel_config_with_payload(
            &repo,
            Some(&payloads),
            TunnelSaveDraft {
                id: Some(created.id),
                name: "wg".into(),
                kind: Some(TunnelKind::WireGuard),
                payload: Some(b"v2".to_vec()),
            },
            &[],
        )
        .unwrap();
        assert!(edited.updated_at.unwrap() > first_stamp);
        assert_eq!(payloads.read(&created.id).unwrap().unwrap(), b"v2");
    }

    #[test]
    fn save_trims_name_on_commit() {
        let lab = FakeTunnelEditorLab::new();
        let mut vm = TunnelEditorDialogVm::new();
        vm.set_name("  trimmed  ");
        vm.set_kind(TunnelKind::WireGuard);
        let saved = vm.save_to_lab(&lab).unwrap();
        assert_eq!(saved.name, "trimmed");
    }

    #[cfg(feature = "secrets")]
    #[test]
    fn lab_debug_omits_payload_bytes() {
        let lab = FakeTunnelEditorLab::with_config(
            row("x", TunnelKind::WireGuard),
            Some(vec![1, 2, 3]),
        );
        let debug = format!("{lab:?}");
        assert!(debug.contains("entry_byte_lengths"));
        assert!(!debug.contains("[1, 2, 3]"));
    }
}
