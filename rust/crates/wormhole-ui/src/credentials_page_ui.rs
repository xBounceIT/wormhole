//! Credentials page list / CRUD Fake VM glue (C# `CredentialsViewModel` metadata subset).
//!
//! Lists credential metadata via [`CredentialPageSource`] (`FakeCredentialPageStore` in tests;
//! optional [`StorageCredentialPageSource`] behind `--features storage`; optional
//! [`CatalogCredentialPageSource`] behind `--features secrets`). Never puts password bodies
//! in list rows or [`Debug`]. Composes [`filter_credential_profiles`] / [`profile_matches_query`]
//! for search and storage [`credential_glue`] + [`PasswordStore`] for CRUD when `storage` is on.
//! No GPUI chrome; debounce is host-owned (C# 120ms on `CredentialsViewModel`).

use std::collections::HashSet;
use std::fmt;
use std::sync::Mutex;

use chrono::{DateTime, Utc};
use thiserror::Error;
use uuid::Uuid;
use wormhole_domain::{
    CredentialKind, CredentialSecretProvider, ProtocolType, BITWARDEN_PASSWORD_FIELD_PATH,
};

use crate::credential_picker::{
    filter_credential_profiles, profile_matches_query, CredentialProfileRow,
};

/// Errors from credential-page list load (never secret payloads).
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CredentialPageError {
    #[error("failed to load credentials: {0}")]
    Load(String),
}

/// CRUD errors for the credentials page glue (never carry password material).
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CredentialsPageCrudError {
    #[error("credential name already in use")]
    NameInUse,
    #[error("credential is read-only")]
    ReadOnly,
    #[error("SSH key credentials are not editable from the credentials page")]
    NotEditableKind,
    #[error("credential not found")]
    NotFound,
    #[error("storage error: {0}")]
    Storage(String),
    #[error("password store error: {0}")]
    PasswordStore(String),
    #[cfg(feature = "secrets")]
    #[error("password resolve error: {0}")]
    PasswordResolve(String),
}

/// Metadata-only credential row for the credentials page list / selection / CRUD.
///
/// Deliberately omits password bodies. [`Debug`] is safe for logs.
#[derive(Clone, PartialEq, Eq)]
pub struct CredentialPageRow {
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
    pub created_at: DateTime<Utc>,
    /// Virtual Bitwarden cache projection (C# `IsVirtualBitwarden`).
    pub is_virtual_bitwarden: bool,
}

impl CredentialPageRow {
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

    /// C# `IsReadOnly` — virtual Bitwarden rows cannot be edited/deleted here.
    pub fn is_read_only(&self) -> bool {
        self.is_virtual_bitwarden
    }

    fn as_search_row(&self) -> CredentialProfileRow {
        CredentialProfileRow::new(
            self.id,
            self.name.clone(),
            self.username.clone(),
            self.domain.clone(),
        )
    }
}

impl fmt::Debug for CredentialPageRow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CredentialPageRow")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("username", &self.username)
            .field("domain", &self.domain)
            .field("kind", &self.kind)
            .field("protocol", &self.protocol)
            .field("secret_provider", &self.secret_provider)
            .field("is_virtual_bitwarden", &self.is_virtual_bitwarden)
            .finish()
    }
}

/// Draft for add/edit dialogs — password stays out of list rows and [`Debug`].
#[derive(Clone)]
pub struct CredentialSaveDraft {
    pub id: Option<Uuid>,
    pub name: String,
    pub username: Option<String>,
    pub domain: Option<String>,
    pub protocol: ProtocolType,
    pub kind: CredentialKind,
    pub secret_provider: CredentialSecretProvider,
    pub bitwarden_item_id: Option<String>,
    pub bitwarden_item_name: Option<String>,
    pub bitwarden_field_path: Option<String>,
    password: String,
}

impl CredentialSaveDraft {
    pub fn new_local_password(name: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            id: None,
            name: name.into(),
            username: None,
            domain: None,
            protocol: ProtocolType::Ssh,
            kind: CredentialKind::Password,
            secret_provider: CredentialSecretProvider::Local,
            bitwarden_item_id: None,
            bitwarden_item_name: None,
            bitwarden_field_path: Some(BITWARDEN_PASSWORD_FIELD_PATH.to_owned()),
            password: password.into(),
        }
    }

    pub fn password(&self) -> &str {
        &self.password
    }

    pub fn set_password(&mut self, password: impl Into<String>) {
        self.password = password.into();
    }
}

impl fmt::Debug for CredentialSaveDraft {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CredentialSaveDraft")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("protocol", &self.protocol)
            .field("secret_provider", &self.secret_provider)
            .field("password_len", &self.password.len())
            .finish()
    }
}

/// Loads credential page metadata (Fake in tests; SQLite / catalog adapters optional).
pub trait CredentialPageSource {
    fn list_all(&self) -> Result<Vec<CredentialPageRow>, CredentialPageError>;
}

/// In-memory Fake store for unit tests (metadata + optional paired password Fake).
#[derive(Default)]
pub struct FakeCredentialPageStore {
    inner: Mutex<FakeCredentialPageStoreInner>,
}

#[derive(Default)]
struct FakeCredentialPageStoreInner {
    rows: Vec<CredentialPageRow>,
    fail: Option<String>,
}

impl FakeCredentialPageStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_rows(rows: impl IntoIterator<Item = CredentialPageRow>) -> Self {
        Self {
            inner: Mutex::new(FakeCredentialPageStoreInner {
                rows: rows.into_iter().collect(),
                fail: None,
            }),
        }
    }

    pub fn failing(message: impl Into<String>) -> Self {
        Self {
            inner: Mutex::new(FakeCredentialPageStoreInner {
                rows: Vec::new(),
                fail: Some(message.into()),
            }),
        }
    }

    pub fn set_rows(&self, rows: impl IntoIterator<Item = CredentialPageRow>) {
        let mut guard = self.inner.lock().expect("FakeCredentialPageStore mutex poisoned");
        guard.rows = rows.into_iter().collect();
        guard.fail = None;
    }

    /// Lab CRUD: insert metadata row (password via separate [`wormhole_secrets_win::FakePasswordStore`]).
    pub fn insert_row(&self, row: CredentialPageRow) -> Result<(), CredentialPageError> {
        let mut guard = self.inner.lock().expect("FakeCredentialPageStore mutex poisoned");
        if guard.fail.is_some() {
            return Err(CredentialPageError::Load(
                guard.fail.clone().unwrap_or_default(),
            ));
        }
        let index = sorted_index_for(&guard.rows, &row.name);
        guard.rows.insert(index, row);
        Ok(())
    }

    pub fn update_row(&self, updated: CredentialPageRow) -> Result<(), CredentialPageError> {
        let mut guard = self.inner.lock().expect("FakeCredentialPageStore mutex poisoned");
        if guard.fail.is_some() {
            return Err(CredentialPageError::Load(
                guard.fail.clone().unwrap_or_default(),
            ));
        }
        let Some(index) = guard.rows.iter().position(|r| r.id == updated.id) else {
            return Err(CredentialPageError::Load("credential not found".into()));
        };
        if guard.rows[index].name != updated.name {
            guard.rows.remove(index);
            let insert_at = sorted_index_for(&guard.rows, &updated.name);
            guard.rows.insert(insert_at, updated);
        } else {
            guard.rows[index] = updated;
        }
        Ok(())
    }

    pub fn delete_row(&self, id: Uuid) -> Result<(), CredentialPageError> {
        let mut guard = self.inner.lock().expect("FakeCredentialPageStore mutex poisoned");
        if guard.fail.is_some() {
            return Err(CredentialPageError::Load(
                guard.fail.clone().unwrap_or_default(),
            ));
        }
        let len_before = guard.rows.len();
        guard.rows.retain(|r| r.id != id);
        if guard.rows.len() == len_before {
            return Err(CredentialPageError::Load("credential not found".into()));
        }
        Ok(())
    }
}

impl fmt::Debug for FakeCredentialPageStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let guard = self.inner.lock().expect("FakeCredentialPageStore mutex poisoned");
        f.debug_struct("FakeCredentialPageStore")
            .field("len", &guard.rows.len())
            .field("failing", &guard.fail.is_some())
            .finish()
    }
}

impl CredentialPageSource for FakeCredentialPageStore {
    fn list_all(&self) -> Result<Vec<CredentialPageRow>, CredentialPageError> {
        let guard = self.inner.lock().expect("FakeCredentialPageStore mutex poisoned");
        if let Some(msg) = &guard.fail {
            return Err(CredentialPageError::Load(msg.clone()));
        }
        Ok(guard.rows.clone())
    }
}

impl CredentialPageSource for &FakeCredentialPageStore {
    fn list_all(&self) -> Result<Vec<CredentialPageRow>, CredentialPageError> {
        (*self).list_all()
    }
}

#[cfg(feature = "storage")]
pub struct StorageCredentialPageSource<'a> {
    repo: wormhole_storage::CredentialRepository<'a>,
}

#[cfg(feature = "storage")]
impl<'a> StorageCredentialPageSource<'a> {
    pub fn new(repo: wormhole_storage::CredentialRepository<'a>) -> Self {
        Self { repo }
    }
}

#[cfg(feature = "storage")]
impl CredentialPageSource for StorageCredentialPageSource<'_> {
    fn list_all(&self) -> Result<Vec<CredentialPageRow>, CredentialPageError> {
        self.repo
            .list_all()
            .map(|rows| rows.into_iter().map(CredentialPageRow::from).collect())
            .map_err(|e| CredentialPageError::Load(e.to_string()))
    }
}

#[cfg(feature = "storage")]
impl From<wormhole_storage::CredentialProfile> for CredentialPageRow {
    fn from(value: wormhole_storage::CredentialProfile) -> Self {
        Self {
            id: value.id,
            name: value.name,
            username: value.username,
            domain: value.domain,
            kind: value.kind,
            private_key_file_name: value.private_key_file_name,
            protocol: value.protocol,
            secret_provider: value.secret_provider,
            bitwarden_item_id: value.bitwarden_item_id,
            bitwarden_item_name: value.bitwarden_item_name,
            bitwarden_field_path: value.bitwarden_field_path,
            created_at: value.created_at,
            is_virtual_bitwarden: false,
        }
    }
}

#[cfg(feature = "secrets")]
pub struct CatalogCredentialPageSource<L, C, S>
where
    L: wormhole_secrets_win::LocalCredentialCatalog,
    C: wormhole_secrets_win::BitwardenCredentialCacheSource,
    S: wormhole_secrets_win::BitwardenSession,
{
    catalog: wormhole_secrets_win::BitwardenCredentialCatalogGlue<L, C, S>,
}

#[cfg(feature = "secrets")]
impl<L, C, S> CatalogCredentialPageSource<L, C, S>
where
    L: wormhole_secrets_win::LocalCredentialCatalog,
    C: wormhole_secrets_win::BitwardenCredentialCacheSource,
    S: wormhole_secrets_win::BitwardenSession,
{
    pub fn new(catalog: wormhole_secrets_win::BitwardenCredentialCatalogGlue<L, C, S>) -> Self {
        Self { catalog }
    }
}

#[cfg(feature = "secrets")]
impl<L, C, S> CredentialPageSource for CatalogCredentialPageSource<L, C, S>
where
    L: wormhole_secrets_win::LocalCredentialCatalog,
    C: wormhole_secrets_win::BitwardenCredentialCacheSource,
    S: wormhole_secrets_win::BitwardenSession,
{
    fn list_all(&self) -> Result<Vec<CredentialPageRow>, CredentialPageError> {
        self.catalog
            .credential_page_profiles()
            .map(|rows| rows.into_iter().map(CredentialPageRow::from).collect())
            .map_err(|e| CredentialPageError::Load(e.to_string()))
    }
}

#[cfg(feature = "secrets")]
impl From<wormhole_secrets_win::BitwardenCatalogProfile> for CredentialPageRow {
    fn from(value: wormhole_secrets_win::BitwardenCatalogProfile) -> Self {
        Self {
            id: value.id,
            name: value.name,
            username: value.username,
            domain: value.domain,
            kind: value.kind,
            private_key_file_name: value.private_key_file_name,
            protocol: value.protocol,
            secret_provider: value.secret_provider,
            bitwarden_item_id: value.bitwarden_item_id,
            bitwarden_item_name: value.bitwarden_item_name,
            bitwarden_field_path: value.bitwarden_field_path,
            created_at: value.created_at,
            is_virtual_bitwarden: value.is_virtual_bitwarden,
        }
    }
}

/// Credentials-page filter: name **or** username **or** domain (C# `MatchesQuery`).
pub fn filter_credentials_page(rows: &[CredentialPageRow], query: &str) -> Vec<CredentialPageRow> {
    let trimmed = query.trim();
    if trimmed.is_empty() {
        return rows.to_vec();
    }
    rows.iter()
        .filter(|row| profile_matches_query(&row.as_search_row(), trimmed))
        .cloned()
        .collect()
}

/// C# `NameExists` — case-insensitive; skips virtual Bitwarden rows.
pub fn credential_name_exists(
    credentials: &[CredentialPageRow],
    name: &str,
    excluding_id: Option<Uuid>,
) -> bool {
    credentials.iter().any(|c| {
        !c.is_virtual_bitwarden
            && excluding_id.map_or(true, |id| c.id != id)
            && c.name.eq_ignore_ascii_case(name)
    })
}

fn sorted_index_for(rows: &[CredentialPageRow], name: &str) -> usize {
    rows.iter().position(|r| r.name.as_str() > name).unwrap_or(rows.len())
}

/// Credentials page VM — list + search + multi-select (metadata only).
///
/// **Load semantics:** successful [`load_from`](Self::load_from) **replaces** the cached
/// snapshot and **clears selection** (C# `LoadAsync`). On `Err`, prior list / search /
/// selection are left untouched (**last-good**). No debounce (host owns it).
#[derive(Clone)]
pub struct CredentialsPageVm {
    credentials: Vec<CredentialPageRow>,
    search_text: String,
    selected_ids: HashSet<Uuid>,
    loaded: bool,
}

impl Default for CredentialsPageVm {
    fn default() -> Self {
        Self::new()
    }
}

impl CredentialsPageVm {
    pub fn new() -> Self {
        Self {
            credentials: Vec::new(),
            search_text: String::new(),
            selected_ids: HashSet::new(),
            loaded: false,
        }
    }

    pub fn from_credentials(credentials: impl IntoIterator<Item = CredentialPageRow>) -> Self {
        Self {
            credentials: credentials.into_iter().collect(),
            search_text: String::new(),
            selected_ids: HashSet::new(),
            loaded: true,
        }
    }

    pub fn load_from<S: CredentialPageSource + ?Sized>(
        &mut self,
        source: &S,
    ) -> Result<(), CredentialPageError> {
        self.credentials = source.list_all()?;
        self.selected_ids.clear();
        self.loaded = true;
        self.prune_selection();
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

    pub fn credentials(&self) -> &[CredentialPageRow] {
        &self.credentials
    }

    pub fn filtered(&self) -> Vec<CredentialPageRow> {
        filter_credentials_page(&self.credentials, &self.search_text)
    }

    pub fn is_empty(&self) -> bool {
        self.credentials.is_empty()
    }

    pub fn has_matches(&self) -> bool {
        !self.filtered().is_empty()
    }

    pub fn has_no_matches(&self) -> bool {
        !self.is_empty() && !self.has_matches()
    }

    pub fn can_select_all(&self) -> bool {
        self.has_matches()
    }

    pub fn has_selection(&self) -> bool {
        !self.selected_ids.is_empty()
    }

    pub fn selected_count(&self) -> usize {
        self.selected_ids.len()
    }

    pub fn is_selected(&self, id: Uuid) -> bool {
        self.selected_ids.contains(&id)
    }

    pub fn select(&mut self, id: Uuid) {
        if self.credentials.iter().any(|c| c.id == id) {
            self.selected_ids.insert(id);
        }
    }

    pub fn deselect(&mut self, id: Uuid) {
        self.selected_ids.remove(&id);
    }

    pub fn toggle_select(&mut self, id: Uuid) {
        if self.is_selected(id) {
            self.deselect(id);
        } else {
            self.select(id);
        }
    }

    pub fn clear_selection(&mut self) {
        self.selected_ids.clear();
    }

    /// Add every filtered row not already selected (C# `SelectAll`).
    pub fn select_all_filtered(&mut self) {
        for row in self.filtered() {
            self.selected_ids.insert(row.id);
        }
    }

    /// Deletable selection snapshot (non-read-only), stable order.
    pub fn deletable_selected(&self) -> Vec<CredentialPageRow> {
        self.credentials
            .iter()
            .filter(|c| self.selected_ids.contains(&c.id) && !c.is_read_only())
            .cloned()
            .collect()
    }

    pub fn can_delete_selected(&self) -> bool {
        !self.deletable_selected().is_empty()
    }

    /// In-place insert at name-sorted position (C# `SortedIndexFor` after add).
    pub fn insert_sorted(&mut self, row: CredentialPageRow) {
        let index = sorted_index_for(&self.credentials, &row.name);
        self.credentials.insert(index, row);
    }

    /// In-place replace; rename moves to sorted position (C# `ReplaceInPlace`).
    pub fn replace_in_place(&mut self, original_id: Uuid, updated: CredentialPageRow) {
        let was_selected = self.selected_ids.remove(&original_id);
        let Some(index) = self.credentials.iter().position(|c| c.id == original_id) else {
            self.insert_sorted(updated.clone());
            if was_selected {
                self.selected_ids.insert(updated.id);
            }
            return;
        };
        let original_name = self.credentials[index].name.clone();
        if original_name == updated.name {
            self.credentials[index] = updated.clone();
        } else {
            self.credentials.remove(index);
            let insert_at = sorted_index_for(&self.credentials, &updated.name);
            self.credentials.insert(insert_at, updated.clone());
        }
        if was_selected {
            self.selected_ids.insert(updated.id);
        }
    }

    /// Remove row + drop from selection (C# delete UI ordering before secret cleanup).
    pub fn remove(&mut self, id: Uuid) {
        self.credentials.retain(|c| c.id != id);
        self.selected_ids.remove(&id);
    }

    fn prune_selection(&mut self) {
        self.selected_ids
            .retain(|id| self.credentials.iter().any(|c| c.id == *id));
    }
}

impl fmt::Debug for CredentialsPageVm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CredentialsPageVm")
            .field("credential_count", &self.credentials.len())
            .field("search_len", &self.search_text.len())
            .field("selected_count", &self.selected_ids.len())
            .field("loaded", &self.loaded)
            .finish()
    }
}

#[cfg(feature = "storage")]
pub fn add_credential_profile(
    repo: &wormhole_storage::CredentialRepository<'_>,
    passwords: &dyn wormhole_secrets_win::PasswordStore,
    draft: CredentialSaveDraft,
    existing_names: &[CredentialPageRow],
) -> Result<CredentialPageRow, CredentialsPageCrudError> {
    if credential_name_exists(existing_names, &draft.name, None) {
        return Err(CredentialsPageCrudError::NameInUse);
    }
    let id = draft.id.unwrap_or_else(Uuid::new_v4);
    let password = draft.password().to_owned();
    let profile_draft = wormhole_storage::CredentialProfileDraft {
        id,
        name: draft.name,
        username: draft.username,
        domain: draft.domain,
        kind: draft.kind,
        private_key_file_name: None,
        protocol: draft.protocol,
        secret_provider: draft.secret_provider,
        bitwarden_item_id: draft.bitwarden_item_id,
        bitwarden_item_name: draft.bitwarden_item_name,
        bitwarden_field_path: draft.bitwarden_field_path,
    };
    let stored = wormhole_storage::create_credential_profile(repo, profile_draft)
        .map_err(|e| CredentialsPageCrudError::Storage(e.to_string()))?;
    if stored.secret_provider == CredentialSecretProvider::Local {
        if let Err(e) = passwords.store(&stored.id, &password) {
            let _ = repo.delete(stored.id);
            return Err(CredentialsPageCrudError::PasswordStore(e.to_string()));
        }
    }
    Ok(CredentialPageRow::from(stored))
}

#[cfg(feature = "storage")]
pub fn update_credential_profile(
    repo: &wormhole_storage::CredentialRepository<'_>,
    passwords: &dyn wormhole_secrets_win::PasswordStore,
    original: &CredentialPageRow,
    draft: CredentialSaveDraft,
    existing_names: &[CredentialPageRow],
) -> Result<CredentialPageRow, CredentialsPageCrudError> {
    if original.is_read_only() {
        return Err(CredentialsPageCrudError::ReadOnly);
    }
    if original.kind != CredentialKind::Password {
        return Err(CredentialsPageCrudError::NotEditableKind);
    }
    if credential_name_exists(existing_names, &draft.name, Some(original.id)) {
        return Err(CredentialsPageCrudError::NameInUse);
    }
    let password = draft.password().to_owned();
    let mut updated = repo
        .get_by_id(original.id)
        .map_err(|e| CredentialsPageCrudError::Storage(e.to_string()))?
        .ok_or(CredentialsPageCrudError::NotFound)?;
    updated.name = draft.name;
    updated.username = draft.username;
    updated.domain = draft.domain;
    updated.protocol = draft.protocol;
    updated.secret_provider = draft.secret_provider;
    updated.bitwarden_item_id = draft.bitwarden_item_id;
    updated.bitwarden_item_name = draft.bitwarden_item_name;
    updated.bitwarden_field_path = draft.bitwarden_field_path;
    repo.update(&updated)
        .map_err(|e| CredentialsPageCrudError::Storage(e.to_string()))?;
    let refreshed = repo
        .get_by_id(original.id)
        .map_err(|e| CredentialsPageCrudError::Storage(e.to_string()))?
        .ok_or(CredentialsPageCrudError::NotFound)?;
    if refreshed.secret_provider == CredentialSecretProvider::Local {
        passwords
            .store(&refreshed.id, &password)
            .map_err(|e| CredentialsPageCrudError::PasswordStore(e.to_string()))?;
    } else {
        let _ = passwords.delete(&refreshed.id);
    }
    Ok(CredentialPageRow::from(refreshed))
}

#[cfg(feature = "storage")]
pub fn delete_credential_profile_page(
    repo: &wormhole_storage::CredentialRepository<'_>,
    passwords: &dyn wormhole_secrets_win::PasswordStore,
    row: &CredentialPageRow,
    secrets: Option<&dyn wormhole_storage::CredentialSecrets>,
) -> Result<(), CredentialsPageCrudError> {
    if row.is_read_only() {
        return Err(CredentialsPageCrudError::ReadOnly);
    }
    wormhole_storage::delete_credential_profile(repo, row.id, secrets)
        .map_err(|e| CredentialsPageCrudError::Storage(e.to_string()))?;
    let _ = passwords.delete(&row.id);
    Ok(())
}

#[cfg(feature = "secrets")]
pub fn read_password_for_edit<P, S, V>(
    resolver: &wormhole_secrets_win::CredentialPasswordResolverGlue<P, S, V>,
    row: &CredentialPageRow,
) -> Result<String, CredentialsPageCrudError>
where
    P: wormhole_secrets_win::PasswordStore + Send + Sync,
    S: wormhole_secrets_win::BitwardenSession,
    V: wormhole_secrets_win::BitwardenVaultPasswordSource,
{
    use wormhole_secrets_win::CredentialPasswordResolver;
    if row.kind != CredentialKind::Password {
        return Err(CredentialsPageCrudError::NotEditableKind);
    }
    if row.secret_provider != CredentialSecretProvider::Local {
        return Ok(String::new());
    }
    let profile = wormhole_secrets_win::BitwardenCatalogProfile::local_password(
        row.id,
        row.name.clone(),
        row.protocol,
        row.username.clone(),
    );
    resolver
        .read_password(&profile)
        .map_err(|e| CredentialsPageCrudError::PasswordResolve(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn ts() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap()
    }

    fn row(name: &str, username: Option<&str>, domain: Option<&str>) -> CredentialPageRow {
        CredentialPageRow {
            id: Uuid::new_v4(),
            name: name.into(),
            username: username.map(str::to_string),
            domain: domain.map(str::to_string),
            kind: CredentialKind::Password,
            private_key_file_name: None,
            protocol: ProtocolType::Ssh,
            secret_provider: CredentialSecretProvider::Local,
            bitwarden_item_id: None,
            bitwarden_item_name: None,
            bitwarden_field_path: Some(BITWARDEN_PASSWORD_FIELD_PATH.to_owned()),
            created_at: ts(),
            is_virtual_bitwarden: false,
        }
    }

    fn virtual_row(name: &str) -> CredentialPageRow {
        let mut r = row(name, Some("bw-user"), None);
        r.is_virtual_bitwarden = true;
        r.secret_provider = CredentialSecretProvider::Bitwarden;
        r
    }

    #[test]
    fn filter_matches_name_username_domain() {
        let a = row("prod-ssh", Some("ops"), None);
        let b = row("other", Some("alice"), None);
        let c = row("rdp", Some("user"), Some("CONTOSO"));
        let rows = vec![a.clone(), b.clone(), c.clone()];
        assert_eq!(filter_credentials_page(&rows, ""), rows);
        assert_eq!(filter_credentials_page(&rows, "PROD"), vec![a]);
        assert_eq!(filter_credentials_page(&rows, "alice"), vec![b]);
        assert_eq!(filter_credentials_page(&rows, "contoso"), vec![c]);
    }

    #[test]
    fn name_exists_ignores_virtual_and_excluded_id() {
        let local = row("Alpha", None, None);
        let virt = virtual_row("Alpha");
        let creds = vec![local.clone(), virt];
        assert!(credential_name_exists(&creds, "alpha", None));
        assert!(!credential_name_exists(&creds, "alpha", Some(local.id)));
        assert!(!credential_name_exists(&creds, "missing", None));
    }

    #[test]
    fn vm_load_replace_selection_clear_and_last_good() {
        let a = row("alpha", None, None);
        let mut vm = CredentialsPageVm::from_credentials([a.clone()]);
        vm.select(a.id);
        vm.set_search_text("alpha");

        let failing = FakeCredentialPageStore::failing("db down");
        let err = vm.load_from(&failing).unwrap_err();
        assert_eq!(err, CredentialPageError::Load("db down".into()));
        assert_eq!(vm.credentials(), &[a.clone()]);
        assert!(vm.is_selected(a.id));
        assert_eq!(vm.search_text(), "alpha");

        let b = row("beta", None, None);
        vm.load_from(&FakeCredentialPageStore::with_rows([b.clone()]))
            .unwrap();
        assert_eq!(vm.credentials().len(), 1);
        assert!(!vm.has_selection());
    }

    #[test]
    fn vm_select_all_and_deletable_selected() {
        let local = row("local", None, None);
        let virt = virtual_row("virt");
        let mut vm = CredentialsPageVm::from_credentials([local.clone(), virt.clone()]);
        vm.select(virt.id);
        assert!(!vm.can_delete_selected());
        vm.select_all_filtered();
        assert_eq!(vm.selected_count(), 2);
        assert_eq!(vm.deletable_selected(), vec![local]);
    }

    #[test]
    fn vm_replace_in_place_migrates_selection_on_rename() {
        let original = row("alpha", None, None);
        let mut vm = CredentialsPageVm::from_credentials([original.clone()]);
        vm.select(original.id);
        let mut updated = original.clone();
        updated.name = "zulu".into();
        vm.replace_in_place(original.id, updated.clone());
        assert!(vm.is_selected(updated.id));
        assert_eq!(vm.credentials()[0].name, "zulu");
    }

    #[test]
    fn vm_empty_and_no_matches_flags() {
        let mut vm = CredentialsPageVm::new();
        vm.load_from(&FakeCredentialPageStore::new()).unwrap();
        assert!(vm.is_empty());
        assert!(!vm.has_matches());
        assert!(!vm.has_no_matches());

        vm.load_from(&FakeCredentialPageStore::with_rows([row("vpn", None, None)]))
            .unwrap();
        vm.set_search_text("nope");
        assert!(!vm.is_empty());
        assert!(!vm.has_matches());
        assert!(vm.has_no_matches());
    }

    #[test]
    fn fake_store_crud_sorted_insert_and_update_rename() {
        let store = FakeCredentialPageStore::new();
        let b = row("beta", None, None);
        let a = row("alpha", None, None);
        store.insert_row(b.clone()).unwrap();
        store.insert_row(a.clone()).unwrap();
        assert_eq!(
            store.list_all().unwrap().into_iter().map(|r| r.name).collect::<Vec<_>>(),
            vec!["alpha", "beta"]
        );
        let mut renamed = a.clone();
        renamed.name = "charlie".into();
        store.update_row(renamed).unwrap();
        assert_eq!(
            store.list_all().unwrap().into_iter().map(|r| r.name).collect::<Vec<_>>(),
            vec!["beta", "charlie"]
        );
        store.delete_row(b.id).unwrap();
        assert_eq!(store.list_all().unwrap().len(), 1);
    }

    #[test]
    fn debug_omits_password_fields() {
        let r = row("vpn", Some("u"), Some("d"));
        let dbg = format!("{r:?}");
        assert!(!dbg.contains("password:"));
        assert!(!dbg.contains("private_key:"));

        let draft = CredentialSaveDraft::new_local_password("n", "super-secret-never-log");
        let draft_dbg = format!("{draft:?}");
        assert!(draft_dbg.contains("password_len"));
        assert!(!draft_dbg.contains("super-secret"));

        let mut vm = CredentialsPageVm::new();
        vm.set_search_text("needle-not-in-debug");
        let vm_dbg = format!("{vm:?}");
        assert!(vm_dbg.contains("search_len"));
        assert!(!vm_dbg.contains("needle-not-in-debug"));
    }

    #[test]
    fn filter_delegates_to_picker_matcher_stable_order() {
        let profiles = vec![
            row("Prod-SSH", Some("ops"), None),
            row("other", Some("ops"), None),
            row("prod-web", Some("www"), None),
        ];
        let search_rows: Vec<_> = profiles
            .iter()
            .map(|p| p.as_search_row())
            .collect();
        let picker_filtered = filter_credential_profiles(&search_rows, "PROD");
        let page_filtered = filter_credentials_page(&profiles, "PROD");
        assert_eq!(
            page_filtered.iter().map(|r| r.id).collect::<Vec<_>>(),
            picker_filtered.iter().map(|r| r.id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn vm_select_rejects_unknown_id() {
        let mut vm = CredentialsPageVm::from_credentials([row("vpn", None, None)]);
        vm.select(Uuid::new_v4());
        assert!(!vm.has_selection());
    }

    #[cfg(feature = "storage")]
    #[test]
    fn add_rolls_back_metadata_when_password_store_fails() {
        use tempfile::tempdir;
        use wormhole_secrets_win::{FakePasswordStore, PasswordStore, SecretsError};
        use wormhole_storage::{
            CredentialRepository, MigrationRunner, SqliteConnectionFactory,
        };

        struct FailingStore;
        impl PasswordStore for FailingStore {
            fn store(&self, _id: &Uuid, _password: &str) -> wormhole_secrets_win::Result<()> {
                Err(SecretsError::UnsupportedPlatform)
            }
            fn read(&self, _id: &Uuid) -> wormhole_secrets_win::Result<Option<String>> {
                Ok(None)
            }
            fn delete(&self, _id: &Uuid) -> wormhole_secrets_win::Result<()> {
                Ok(())
            }
        }

        let dir = tempdir().unwrap();
        let factory = SqliteConnectionFactory::new(dir.path().join("wormhole.db"));
        MigrationRunner::embedded().run(&factory).unwrap();
        let repo = CredentialRepository::new(&factory);
        let draft = CredentialSaveDraft::new_local_password("orphan-guard", "pw");
        let err = add_credential_profile(&repo, &FailingStore, draft, &[]).unwrap_err();
        assert!(matches!(err, CredentialsPageCrudError::PasswordStore(_)));
        assert!(repo.list_all().unwrap().is_empty());

        // control: happy path still works with FakePasswordStore
        let passwords = FakePasswordStore::new();
        let ok = add_credential_profile(
            &repo,
            &passwords,
            CredentialSaveDraft::new_local_password("ok", "pw"),
            &[],
        )
        .unwrap();
        assert_eq!(repo.list_all().unwrap().len(), 1);
        assert_eq!(passwords.read(&ok.id).unwrap().as_deref(), Some("pw"));
    }

    #[cfg(feature = "storage")]
    #[test]
    fn crud_rejects_read_only_and_duplicate_name() {
        use tempfile::tempdir;
        use wormhole_secrets_win::FakePasswordStore;
        use wormhole_storage::{
            CredentialRepository, MemoryCredentialSecrets, MigrationRunner, SqliteConnectionFactory,
        };

        let dir = tempdir().unwrap();
        let factory = SqliteConnectionFactory::new(dir.path().join("wormhole.db"));
        MigrationRunner::embedded().run(&factory).unwrap();
        let repo = CredentialRepository::new(&factory);
        let passwords = FakePasswordStore::new();
        let secrets = MemoryCredentialSecrets::new();
        let virt = virtual_row("bw");
        assert_eq!(
            delete_credential_profile_page(&repo, &passwords, &virt, Some(&secrets)),
            Err(CredentialsPageCrudError::ReadOnly)
        );

        let created = add_credential_profile(
            &repo,
            &passwords,
            CredentialSaveDraft::new_local_password("dup", "pw"),
            &[],
        )
        .unwrap();
        let dup_err = add_credential_profile(
            &repo,
            &passwords,
            CredentialSaveDraft::new_local_password("dup", "pw2"),
            &[created.clone()],
        )
        .unwrap_err();
        assert_eq!(dup_err, CredentialsPageCrudError::NameInUse);
    }

    #[cfg(feature = "storage")]
    #[test]
    fn storage_crud_roundtrip_metadata_only_in_list() {
        use tempfile::tempdir;
        use wormhole_secrets_win::{FakePasswordStore, PasswordStore};
        use wormhole_storage::{
            CredentialRepository, MemoryCredentialSecrets, MigrationRunner, SqliteConnectionFactory,
        };

        let dir = tempdir().unwrap();
        let factory = SqliteConnectionFactory::new(dir.path().join("wormhole.db"));
        MigrationRunner::embedded().run(&factory).unwrap();
        let repo = CredentialRepository::new(&factory);
        let passwords = FakePasswordStore::new();
        let secrets = MemoryCredentialSecrets::new();

        let draft = CredentialSaveDraft::new_local_password("lab-ssh", "pw-body-never-in-list");
        let created = add_credential_profile(&repo, &passwords, draft, &[]).unwrap();
        let list_dbg = format!("{created:?}");
        assert!(!list_dbg.contains("pw-body"));
        assert_eq!(passwords.read(&created.id).unwrap().as_deref(), Some("pw-body-never-in-list"));

        let mut edit = CredentialSaveDraft::new_local_password("lab-ssh-renamed", "new-pw");
        edit.id = Some(created.id);
        let updated = update_credential_profile(
            &repo,
            &passwords,
            &created,
            edit,
            &[CredentialPageRow::from(
                repo.get_by_id(created.id).unwrap().unwrap(),
            )],
        )
        .unwrap();
        assert_eq!(updated.name, "lab-ssh-renamed");

        delete_credential_profile_page(
            &repo,
            &passwords,
            &updated,
            Some(&secrets),
        )
        .unwrap();
        assert!(repo.get_by_id(updated.id).unwrap().is_none());
        assert_eq!(passwords.read(&updated.id).unwrap(), None);
        assert_eq!(secrets.deleted_password_ids(), vec![updated.id]);
    }

    #[cfg(feature = "storage")]
    #[test]
    fn storage_source_lists_metadata_only() {
        use tempfile::tempdir;
        use wormhole_storage::{
            create_credential_profile, CredentialProfileDraft, CredentialRepository,
            MigrationRunner, SqliteConnectionFactory,
        };

        let dir = tempdir().unwrap();
        let factory = SqliteConnectionFactory::new(dir.path().join("wormhole.db"));
        MigrationRunner::embedded().run(&factory).unwrap();
        let repo = CredentialRepository::new(&factory);
        let id = Uuid::new_v4();
        create_credential_profile(
            &repo,
            CredentialProfileDraft::local_password(id, "page-row"),
        )
        .unwrap();
        let source = StorageCredentialPageSource::new(repo);
        let rows = source.list_all().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].name, "page-row");
        let dbg = format!("{:?}", rows[0]);
        assert!(!dbg.contains("password:"));
        assert!(!dbg.contains("private_key:"));
    }

    #[cfg(feature = "secrets")]
    #[test]
    fn catalog_source_merges_virtual_rows_when_unlocked() {
        use wormhole_secrets_win::{
            demo_bitwarden_cache_entries, BitwardenCredentialCatalogGlue, BitwardenSession,
            FakeBitwardenCredentialCache, FakeBitwardenSession, FakeLocalCredentialCatalog,
        };

        let local = row("saved", None, None);
        let catalog = BitwardenCredentialCatalogGlue::new(
            FakeLocalCredentialCatalog::with_profiles([wormhole_secrets_win::BitwardenCatalogProfile::local_password(
                local.id,
                local.name.clone(),
                local.protocol,
                local.username.clone(),
            )]),
            FakeBitwardenCredentialCache::with_entries(demo_bitwarden_cache_entries()),
            {
                let s = FakeBitwardenSession::with_session_key("lab");
                assert!(s.unlock("x").unlocked);
                s
            },
            true,
        );
        let source = CatalogCredentialPageSource::new(catalog);
        let rows = source.list_all().unwrap();
        assert!(rows.iter().any(|r| r.name == "saved"));
        assert!(rows.iter().any(|r| r.is_virtual_bitwarden));
    }

    #[cfg(all(feature = "storage", feature = "secrets"))]
    #[test]
    fn read_password_for_edit_local_roundtrip() {
        use wormhole_secrets_win::{
            BitwardenSession, CredentialPasswordResolverGlue, FakeBitwardenSession,
            FakeBitwardenVaultPasswords, FakePasswordStore, PasswordStore,
        };

        let id = Uuid::new_v4();
        let passwords = FakePasswordStore::new();
        passwords.store(&id, "edit-me").unwrap();
        let row = CredentialPageRow::local_password(id, "lab", ProtocolType::Ssh, Some("u".into()));
        let session = FakeBitwardenSession::with_session_key("k");
        assert!(session.unlock("x").unlocked);
        let resolver = CredentialPasswordResolverGlue::new(
            passwords,
            session,
            FakeBitwardenVaultPasswords::new(),
            false,
        );
        assert_eq!(read_password_for_edit(&resolver, &row).unwrap(), "edit-me");
    }
}
