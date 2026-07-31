//! Credential picker search VM glue (pure Rust; no GPUI).
//!
//! Ports C# `CredentialPickerSearch.Filter`: case-insensitive substring on
//! **name** or **username** (plus **domain** for C# `OrdinalIgnoreCase` parity).
//! Empty / whitespace query → all profiles in **stable input order**. Rows are
//! metadata-only — never passwords, private keys, or Bitwarden session material.
//! Secrets stay in CredMgr / DPAPI (`docs/migration/04-secrets.md`).
//!
//! Unit tests inject [`FakeCredentialList`]. SQLite credential-catalog source and
//! GPUI combo chrome are out of scope.

use std::fmt;
use std::sync::Mutex;

use thiserror::Error;
use uuid::Uuid;

/// Errors from credential-profile list load (metadata only — never secret payloads).
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CredentialPickerError {
    #[error("failed to load credential profiles: {0}")]
    Load(String),
}

/// Metadata-only credential row for picker search / display.
///
/// Deliberately omits password, private-key bytes, and Bitwarden session keys so
/// [`Debug`] cannot leak secrets. Filenames / provider flags belong on a fuller
/// domain model later — this stub is search-shaped only.
#[derive(Clone, PartialEq, Eq)]
pub struct CredentialProfileRow {
    pub id: Uuid,
    pub name: String,
    pub username: Option<String>,
    /// Optional Windows / RDP domain (C# `CredentialProfile.Domain`; searchable).
    pub domain: Option<String>,
}

impl CredentialProfileRow {
    /// Construct a row. `name` is stored as-is (trim is a host concern).
    pub fn new(
        id: Uuid,
        name: impl Into<String>,
        username: Option<String>,
        domain: Option<String>,
    ) -> Self {
        Self {
            id,
            name: name.into(),
            username,
            domain,
        }
    }
}

impl fmt::Debug for CredentialProfileRow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Explicit Debug: only non-secret metadata fields exist on this type.
        f.debug_struct("CredentialProfileRow")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("username", &self.username)
            .field("domain", &self.domain)
            .finish()
    }
}

/// Loads credential profile metadata (Fake in tests; SQLite catalog later).
pub trait CredentialProfileSource {
    fn list_all(&self) -> Result<Vec<CredentialProfileRow>, CredentialPickerError>;
}

/// In-memory Fake list for unit tests and headless demos (no CredMgr / DPAPI).
///
/// Mutex-safe so concurrent test hosts can share one list. [`Debug`] reports
/// length + fail flag only — never profile field dumps (defense in depth).
#[derive(Default)]
pub struct FakeCredentialList {
    inner: Mutex<FakeCredentialListInner>,
}

#[derive(Default)]
struct FakeCredentialListInner {
    profiles: Vec<CredentialProfileRow>,
    fail: Option<String>,
}

impl FakeCredentialList {
    /// Empty successful list.
    pub fn new() -> Self {
        Self::default()
    }

    /// Seeded list (order preserved for filter stability).
    pub fn with_profiles(profiles: impl IntoIterator<Item = CredentialProfileRow>) -> Self {
        Self {
            inner: Mutex::new(FakeCredentialListInner {
                profiles: profiles.into_iter().collect(),
                fail: None,
            }),
        }
    }

    /// Always fail `list_all` with the given message (error-path tests).
    pub fn failing(message: impl Into<String>) -> Self {
        Self {
            inner: Mutex::new(FakeCredentialListInner {
                profiles: Vec::new(),
                fail: Some(message.into()),
            }),
        }
    }

    /// Replace the seeded list and clear any fail flag.
    pub fn set_profiles(&self, profiles: impl IntoIterator<Item = CredentialProfileRow>) {
        let mut guard = self.inner.lock().expect("FakeCredentialList mutex poisoned");
        guard.profiles = profiles.into_iter().collect();
        guard.fail = None;
    }
}

impl fmt::Debug for FakeCredentialList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let guard = self.inner.lock().expect("FakeCredentialList mutex poisoned");
        f.debug_struct("FakeCredentialList")
            .field("len", &guard.profiles.len())
            .field("failing", &guard.fail.is_some())
            .finish()
    }
}

impl CredentialProfileSource for FakeCredentialList {
    fn list_all(&self) -> Result<Vec<CredentialProfileRow>, CredentialPickerError> {
        let guard = self.inner.lock().expect("FakeCredentialList mutex poisoned");
        if let Some(msg) = &guard.fail {
            return Err(CredentialPickerError::Load(msg.clone()));
        }
        Ok(guard.profiles.clone())
    }
}

impl CredentialProfileSource for &FakeCredentialList {
    fn list_all(&self) -> Result<Vec<CredentialProfileRow>, CredentialPickerError> {
        (*self).list_all()
    }
}

/// Case-insensitive substring filter over `profiles`.
///
/// - Empty / whitespace `query` → every profile, **stable input order**.
/// - Otherwise → name **or** username **or** domain substring match (C#
///   `StringComparison.OrdinalIgnoreCase`), same relative order.
pub fn filter_credential_profiles(
    profiles: &[CredentialProfileRow],
    query: &str,
) -> Vec<CredentialProfileRow> {
    let trimmed = query.trim();
    if trimmed.is_empty() {
        return profiles.to_vec();
    }
    let query_lower = trimmed.to_lowercase();
    profiles
        .iter()
        .filter(|p| profile_matches_query_lower(p, &query_lower))
        .cloned()
        .collect()
}

/// Same as [`filter_credential_profiles`], loading via a [`CredentialProfileSource`].
pub fn filter_credential_profiles_from<S: CredentialProfileSource + ?Sized>(
    source: &S,
    query: &str,
) -> Result<Vec<CredentialProfileRow>, CredentialPickerError> {
    let profiles = source.list_all()?;
    Ok(filter_credential_profiles(&profiles, query))
}

/// Case-insensitive name / username / domain substring match.
///
/// Empty / whitespace `query` → `false` (callers that want “show all” use
/// [`filter_credential_profiles`] instead).
pub fn profile_matches_query(profile: &CredentialProfileRow, query: &str) -> bool {
    let query_lower = query.trim().to_lowercase();
    if query_lower.is_empty() {
        return false;
    }
    profile_matches_query_lower(profile, &query_lower)
}

fn profile_matches_query_lower(profile: &CredentialProfileRow, query_lower: &str) -> bool {
    // `str::contains("")` is true for every haystack — never treat empty as a match.
    // Public callers (`filter_*` / `profile_matches_query`) already branch on empty/whitespace;
    // this guard keeps the invariant local if a future caller forgets.
    if query_lower.is_empty() {
        return false;
    }
    if profile.name.to_lowercase().contains(query_lower) {
        return true;
    }
    if optional_field_contains(profile.username.as_deref(), query_lower) {
        return true;
    }
    optional_field_contains(profile.domain.as_deref(), query_lower)
}

fn optional_field_contains(value: Option<&str>, query_lower: &str) -> bool {
    value
        .map(str::to_lowercase)
        .is_some_and(|v| v.contains(query_lower))
}

/// Thin search VM: cached Fake/source snapshot + query → filtered rows.
///
/// No debounce (C# `CredentialsViewModel` owns that); hosts may debounce
/// [`set_query`](Self::set_query). No GPUI chrome.
///
/// **Load semantics:** successful [`load_from`](Self::load_from) **replaces** the
/// cached snapshot (does not append). On `Err`, the prior snapshot and query are
/// left untouched (**last-good**, matching C# `CredentialsViewModel.LoadAsync`
/// catch). That differs from “fail-closed wipe”: [`filter_credential_profiles_from`]
/// still returns `Err` without inventing an empty success list.
#[derive(Clone, Default)]
pub struct CredentialPickerSearchVm {
    profiles: Vec<CredentialProfileRow>,
    query: String,
}

impl CredentialPickerSearchVm {
    pub fn new() -> Self {
        Self::default()
    }

    /// Seed from an already-listed snapshot (tests / previews).
    pub fn from_profiles(profiles: impl IntoIterator<Item = CredentialProfileRow>) -> Self {
        Self {
            profiles: profiles.into_iter().collect(),
            query: String::new(),
        }
    }

    /// Replace the cached list from `source` (query unchanged).
    ///
    /// On `Ok`, the previous snapshot is discarded. On `Err`, state is unchanged
    /// (last-good cache + query).
    pub fn load_from<S: CredentialProfileSource + ?Sized>(
        &mut self,
        source: &S,
    ) -> Result<(), CredentialPickerError> {
        self.profiles = source.list_all()?;
        Ok(())
    }

    pub fn set_query(&mut self, query: impl Into<String>) {
        self.query = query.into();
    }

    pub fn query(&self) -> &str {
        &self.query
    }

    /// Full cached snapshot (pre-filter), stable order from last load.
    pub fn profiles(&self) -> &[CredentialProfileRow] {
        &self.profiles
    }

    /// Filtered view of the cached list (empty query → all).
    pub fn filtered(&self) -> Vec<CredentialProfileRow> {
        filter_credential_profiles(&self.profiles, &self.query)
    }
}

impl fmt::Debug for CredentialPickerSearchVm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CredentialPickerSearchVm")
            .field("profile_count", &self.profiles.len())
            .field("query_len", &self.query.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(name: &str, username: Option<&str>, domain: Option<&str>) -> CredentialProfileRow {
        CredentialProfileRow::new(
            Uuid::new_v4(),
            name,
            username.map(str::to_string),
            domain.map(str::to_string),
        )
    }

    #[test]
    fn empty_query_returns_all_stable_order() {
        let a = row("alpha", Some("alice"), None);
        let b = row("beta", Some("bob"), None);
        let c = row("gamma", None, Some("CONTOSO"));
        let profiles = vec![a.clone(), b.clone(), c.clone()];
        assert_eq!(filter_credential_profiles(&profiles, ""), profiles);
        assert_eq!(filter_credential_profiles(&profiles, "   "), profiles);
    }

    #[test]
    fn name_match_case_insensitive_stable_order() {
        let keep_first = row("Prod-SSH", Some("ops"), None);
        let skip = row("other", Some("ops"), None);
        let keep_second = row("prod-web", Some("www"), None);
        let profiles = vec![keep_first.clone(), skip.clone(), keep_second.clone()];
        let filtered = filter_credential_profiles(&profiles, "PROD");
        assert_eq!(filtered, vec![keep_first, keep_second]);
        assert!(!filtered.iter().any(|p| p.id == skip.id));
    }

    #[test]
    fn username_match_case_insensitive() {
        let id = Uuid::new_v4();
        let profiles = vec![CredentialProfileRow::new(
            id,
            "box",
            Some("Alice.Admin".into()),
            None,
        )];
        assert_eq!(
            filter_credential_profiles(&profiles, "alice.admin")
                .into_iter()
                .map(|p| p.id)
                .collect::<Vec<_>>(),
            vec![id]
        );
    }

    #[test]
    fn domain_match_case_insensitive() {
        let id = Uuid::new_v4();
        let profiles = vec![CredentialProfileRow::new(
            id,
            "rdp-lab",
            Some("user".into()),
            Some("Corp.Example".into()),
        )];
        assert_eq!(
            filter_credential_profiles(&profiles, "corp.example")
                .into_iter()
                .map(|p| p.id)
                .collect::<Vec<_>>(),
            vec![id]
        );
    }

    #[test]
    fn no_matches_returns_empty() {
        let profiles = vec![row("box", Some("alice"), None)];
        assert!(filter_credential_profiles(&profiles, "zzz-nope").is_empty());
    }

    #[test]
    fn query_trims_leading_trailing_whitespace() {
        let id = Uuid::new_v4();
        let profiles = vec![CredentialProfileRow::new(
            id,
            "prod-web",
            Some("alice".into()),
            None,
        )];
        assert_eq!(
            filter_credential_profiles(&profiles, "  prod  ")
                .into_iter()
                .map(|p| p.id)
                .collect::<Vec<_>>(),
            vec![id]
        );
        assert!(profile_matches_query(&profiles[0], "  ALICE  "));
        assert!(!profile_matches_query(&profiles[0], ""));
        assert!(!profile_matches_query(&profiles[0], "   "));
    }

    #[test]
    fn none_username_and_domain_match_name_only() {
        let id = Uuid::new_v4();
        let profiles = vec![CredentialProfileRow::new(id, "serial-ops", None, None)];
        assert_eq!(
            filter_credential_profiles(&profiles, "serial")
                .into_iter()
                .map(|p| p.id)
                .collect::<Vec<_>>(),
            vec![id]
        );
        assert!(filter_credential_profiles(&profiles, "alice").is_empty());
    }

    #[test]
    fn empty_snapshot_returns_empty() {
        assert!(filter_credential_profiles(&[], "").is_empty());
        assert!(filter_credential_profiles(&[], "x").is_empty());
    }

    #[test]
    fn fake_list_filter_from_source() {
        let a = row("alpha", Some("alice"), None);
        let b = row("beta", Some("bob"), None);
        let fake = FakeCredentialList::with_profiles([a.clone(), b.clone()]);
        let filtered = filter_credential_profiles_from(&fake, "ali").unwrap();
        assert_eq!(filtered, vec![a]);
        assert_eq!(filter_credential_profiles_from(&fake, "").unwrap().len(), 2);
    }

    #[test]
    fn fake_failing_propagates_load_error() {
        let fake = FakeCredentialList::failing("injected list failure");
        let err = filter_credential_profiles_from(&fake, "x").unwrap_err();
        assert_eq!(
            err,
            CredentialPickerError::Load("injected list failure".into())
        );
    }

    #[test]
    fn vm_load_and_filter() {
        let a = row("Lab SSH", Some("root"), None);
        let b = row("Other", Some("guest"), None);
        let fake = FakeCredentialList::with_profiles([a.clone(), b.clone()]);
        let mut vm = CredentialPickerSearchVm::new();
        vm.load_from(&fake).unwrap();
        assert_eq!(vm.filtered().len(), 2);
        vm.set_query("lab");
        assert_eq!(vm.filtered(), vec![a]);
        vm.set_query("");
        assert_eq!(vm.filtered().len(), 2);
    }

    #[test]
    fn vm_load_replaces_snapshot_not_append() {
        let stale = row("stale", Some("old"), None);
        let fresh = row("fresh", Some("new"), None);
        let mut vm = CredentialPickerSearchVm::from_profiles([stale.clone()]);
        vm.set_query("stale");
        assert_eq!(vm.filtered(), vec![stale.clone()]);

        let fake = FakeCredentialList::with_profiles([fresh.clone()]);
        vm.load_from(&fake).unwrap();
        assert_eq!(vm.profiles(), &[fresh.clone()]);
        assert_eq!(vm.query(), "stale"); // query preserved
        assert!(vm.filtered().is_empty()); // query no longer matches

        let empty = FakeCredentialList::new();
        vm.load_from(&empty).unwrap();
        assert!(vm.profiles().is_empty());
        assert_eq!(vm.query(), "stale");
    }

    #[test]
    fn vm_load_err_keeps_last_good_snapshot_and_query() {
        let a = row("Lab SSH", Some("root"), None);
        let fake_ok = FakeCredentialList::with_profiles([a.clone()]);
        let mut vm = CredentialPickerSearchVm::new();
        vm.load_from(&fake_ok).unwrap();
        vm.set_query("lab");
        assert_eq!(vm.filtered(), vec![a.clone()]);

        let failing = FakeCredentialList::failing("catalog unavailable");
        let err = vm.load_from(&failing).unwrap_err();
        assert_eq!(
            err,
            CredentialPickerError::Load("catalog unavailable".into())
        );
        assert_eq!(vm.profiles(), &[a.clone()]);
        assert_eq!(vm.query(), "lab");
        assert_eq!(vm.filtered(), vec![a]);
    }

    #[test]
    fn fake_set_profiles_clears_fail_flag() {
        let fake = FakeCredentialList::failing("boom");
        assert!(filter_credential_profiles_from(&fake, "").is_err());
        let a = row("alpha", Some("alice"), None);
        fake.set_profiles([a.clone()]);
        assert_eq!(filter_credential_profiles_from(&fake, "ali").unwrap(), vec![a]);
    }

    #[test]
    fn multi_field_match_returns_row_once() {
        let id = Uuid::new_v4();
        let profiles = vec![CredentialProfileRow::new(
            id,
            "alice-box",
            Some("alice".into()),
            Some("ALICE.DOM".into()),
        )];
        let filtered = filter_credential_profiles(&profiles, "alice");
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].id, id);
    }

    #[test]
    fn empty_query_lower_does_not_match_via_contains_empty() {
        // Rust: every string contains ""; matcher must not treat that as a hit.
        let p = row("anything", Some("u"), Some("d"));
        assert!(!profile_matches_query_lower(&p, ""));
        assert!(profile_matches_query_lower(&p, "any"));
    }

    #[test]
    fn empty_string_optional_fields_do_not_match_nonempty_query() {
        let id = Uuid::new_v4();
        let profiles = vec![CredentialProfileRow::new(
            id,
            "lab-ssh",
            Some(String::new()),
            Some(String::new()),
        )];
        assert!(filter_credential_profiles(&profiles, "alice").is_empty());
        assert_eq!(
            filter_credential_profiles(&profiles, "lab")
                .into_iter()
                .map(|p| p.id)
                .collect::<Vec<_>>(),
            vec![id]
        );
    }

    #[test]
    fn debug_omits_secret_shaped_fields_and_avoids_query_echo() {
        let row = CredentialProfileRow::new(
            Uuid::nil(),
            "name",
            Some("user".into()),
            Some("DOMAIN".into()),
        );
        let row_dbg = format!("{row:?}");
        assert!(row_dbg.contains("CredentialProfileRow"));
        assert!(row_dbg.contains("name"));
        assert!(!row_dbg.to_lowercase().contains("password"));
        assert!(!row_dbg.to_lowercase().contains("private_key"));
        assert!(!row_dbg.to_lowercase().contains("secret"));

        let mut vm = CredentialPickerSearchVm::from_profiles([row]);
        vm.set_query("should-not-appear-in-debug");
        let vm_dbg = format!("{vm:?}");
        assert!(vm_dbg.contains("profile_count"));
        assert!(vm_dbg.contains("query_len"));
        assert!(!vm_dbg.contains("should-not-appear-in-debug"));

        let fake = FakeCredentialList::with_profiles([]);
        let fake_dbg = format!("{fake:?}");
        assert!(fake_dbg.contains("len"));
        assert!(!fake_dbg.contains("profiles"));
    }

    #[test]
    fn row_type_has_no_password_field_via_debug_struct_shape() {
        // Compile-time / Debug contract: only id/name/username/domain.
        let row = row("n", Some("u"), Some("d"));
        let dbg = format!("{row:?}");
        assert!(dbg.contains("username"));
        assert!(dbg.contains("domain"));
        assert!(!dbg.contains("password:"));
        assert!(!dbg.contains("private_key"));
        assert!(!dbg.contains("bitwarden"));
    }
}
