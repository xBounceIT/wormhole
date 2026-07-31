//! Regular (non-Bitwarden) HTTP/HTTPS WebView2 profile isolation + startup wipe.
//!
//! Pure Fake glue — **no live WebView2 / GPUI**. Ports:
//! - `WebViewBrowserArguments.KeyedSharedFolderName` / `SweepStaleKeyedFolders`
//! - `AppPaths.GetWebBrowserSharedUserDataDirectory` /
//!   `GetWebBrowserIsolatedUserDataDirectory`
//! - `App.ClearWebBrowserUserData` (wipe `webview2-web\` only)
//! - `WebBrowserView` shared vs isolated selection (SOCKS **or** ignore-cert)
//!
//! Bitwarden extension roots (`bitwarden-browser-webview2\…`) are **never** wiped.
//! Empty / whitespace roots and isolated ids **fail closed**. HTTP(S) is
//! credential-less: [`Debug`] prints lengths / counts / folder-name shapes only.

use std::collections::BTreeSet;
use std::fmt;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::browser_args::HARDENING_BROWSER_ARGS;
use crate::target::{HttpConnectionTarget, Socks5Proxy};
use crate::HttpError;

/// Browser-argument material fingerprinted into [`keyed_shared_folder_name`].
///
/// Shared environments always use hardening-only args (no SOCKS) — see
/// `WebBrowserView.GetOrCreateSharedEnvironmentAsync`.
pub fn keyed_shared_folder_fingerprint_args() -> &'static str {
    HARDENING_BROWSER_ARGS
}

/// `shared-` + first 8 hex chars of SHA-256(hardening args) (C# `KeyedSharedFolderName`).
pub fn keyed_shared_folder_name() -> String {
    let hash = hex_lower(&Sha256::digest(
        keyed_shared_folder_fingerprint_args().as_bytes(),
    ));
    format!("shared-{}", &hash[..8])
}

/// True when a regular web tab needs a dedicated env / UDF (C# `WebBrowserView`).
///
/// Isolation triggers: SOCKS5 proxy **or** **resolved** ignore-cert
/// (`HttpCertPolicy::IgnoreErrors` after scheme gating). Prefer
/// [`target_requires_isolated_web_profile`] so plain HTTP leaf flags cannot force
/// isolation. Raw `ignore_cert_errors` must already be scheme-gated.
pub fn requires_isolated_web_profile(
    socks5: Option<Socks5Proxy>,
    ignore_cert_errors: bool,
) -> bool {
    socks5.is_some() || ignore_cert_errors
}

/// Same decision from a built [`HttpConnectionTarget`] (resolved cert policy).
pub fn target_requires_isolated_web_profile(target: &HttpConnectionTarget) -> bool {
    requires_isolated_web_profile(target.socks5_proxy, target.ignore_cert_errors())
}

/// Shared vs isolated profile kind for a non-extension web tab.
#[derive(Clone, PartialEq, Eq)]
pub enum WebBrowserProfileKind {
    /// Hardening-only shared folder (`shared-<fingerprint>`).
    Shared,
    /// Per-tab `env-<id>` folder (SOCKS and/or ignore-cert).
    Isolated { id: String },
}

impl fmt::Debug for WebBrowserProfileKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Shared => f.write_str("WebBrowserProfileKind::Shared"),
            Self::Isolated { id } => f
                .debug_struct("WebBrowserProfileKind::Isolated")
                .field("id_len", &id.len())
                .finish(),
        }
    }
}

/// Select shared vs isolated kind (fail-closed empty isolated id when isolation needed).
pub fn select_web_browser_profile_kind(
    socks5: Option<Socks5Proxy>,
    ignore_cert_errors: bool,
    isolated_id: &str,
) -> Result<WebBrowserProfileKind, HttpError> {
    if requires_isolated_web_profile(socks5, ignore_cert_errors) {
        let id = require_isolated_id(isolated_id)?;
        Ok(WebBrowserProfileKind::Isolated { id })
    } else {
        Ok(WebBrowserProfileKind::Shared)
    }
}

/// Join `web_root` with the shared argument-keyed folder (fail-closed empty root).
pub fn web_browser_shared_user_data(web_root: &Path) -> Result<PathBuf, HttpError> {
    require_non_empty_path(web_root)?;
    Ok(web_root.join(keyed_shared_folder_name()))
}

/// Join `web_root` with `env-<id>` (fail-closed empty root / id / hostile id).
pub fn web_browser_isolated_user_data(
    web_root: &Path,
    isolated_id: &str,
) -> Result<PathBuf, HttpError> {
    require_non_empty_path(web_root)?;
    let id = require_isolated_id(isolated_id)?;
    Ok(web_root.join(format!("env-{id}")))
}

/// Resolve the concrete user-data folder for a regular web tab under `web_root`.
pub fn select_web_browser_user_data_folder(
    web_root: &Path,
    socks5: Option<Socks5Proxy>,
    ignore_cert_errors: bool,
    isolated_id: &str,
) -> Result<PathBuf, HttpError> {
    match select_web_browser_profile_kind(socks5, ignore_cert_errors, isolated_id)? {
        WebBrowserProfileKind::Shared => web_browser_shared_user_data(web_root),
        // `id` already passed [`require_isolated_id`] in `select_web_browser_profile_kind`.
        WebBrowserProfileKind::Isolated { id } => {
            require_non_empty_path(web_root)?;
            Ok(web_root.join(format!("env-{id}")))
        }
    }
}

/// Target overload — uses resolved SOCKS + [`HttpConnectionTarget::ignore_cert_errors`].
pub fn select_web_browser_user_data_folder_for_target(
    web_root: &Path,
    target: &HttpConnectionTarget,
    isolated_id: &str,
) -> Result<PathBuf, HttpError> {
    select_web_browser_user_data_folder(
        web_root,
        target.socks5_proxy,
        target.ignore_cert_errors(),
        isolated_id,
    )
}

/// Outcome of a Fake / best-effort wipe of the non-extension web root.
#[derive(Clone, PartialEq, Eq)]
pub struct WebBrowserWipeReport {
    /// How many Fake folders were removed under the web root.
    pub removed: usize,
    /// True when the root had no tracked folders (idempotent no-op).
    pub was_empty: bool,
}

impl fmt::Debug for WebBrowserWipeReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebBrowserWipeReport")
            .field("removed", &self.removed)
            .field("was_empty", &self.was_empty)
            .finish()
    }
}

/// Names under `parent` that are stale `shared-*` siblings of `current_keyed`.
///
/// Pure helper matching C# `SweepStaleKeyedFolders` selection (case-insensitive
/// current keep; non-`shared-*` / foreign folders untouched). Empty / whitespace
/// `current_keyed` fails closed as a no-op (returns no deletions) so a missing
/// fingerprint cannot mass-delete every `shared-*` entry. Surrounding whitespace
/// on a non-empty fingerprint is trimmed before the keep comparison. A keep name
/// that is not itself `shared-*` also fails closed (no deletions).
pub fn stale_keyed_folder_names<'a>(
    entries: impl IntoIterator<Item = &'a str>,
    current_keyed: &str,
) -> Vec<String> {
    let current = current_keyed.trim();
    if current.is_empty() || !current.to_ascii_lowercase().starts_with("shared-") {
        return Vec::new();
    }
    entries
        .into_iter()
        .filter(|name| {
            let lower = name.to_ascii_lowercase();
            lower.starts_with("shared-")
                && !lower.eq_ignore_ascii_case(current)
        })
        .map(|s| s.to_string())
        .collect()
}

/// In-memory stand-in for `webview2-web\` (+ separate Bitwarden root).
///
/// Tracks folder names only — no disk I/O, no WebView2. Wipe clears the web root
/// and **never** touches Bitwarden entries.
#[derive(Clone, PartialEq, Eq)]
pub struct FakeWebBrowserProfileStore {
    web_root: PathBuf,
    bitwarden_root: PathBuf,
    web_folders: BTreeSet<String>,
    bitwarden_folders: BTreeSet<String>,
    wipe_count: usize,
    sweep_count: usize,
}

impl fmt::Debug for FakeWebBrowserProfileStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FakeWebBrowserProfileStore")
            .field("web_root_len", &self.web_root.as_os_str().len())
            .field(
                "bitwarden_root_len",
                &self.bitwarden_root.as_os_str().len(),
            )
            .field("web_folder_count", &self.web_folders.len())
            .field("bitwarden_folder_count", &self.bitwarden_folders.len())
            .field("wipe_count", &self.wipe_count)
            .field("sweep_count", &self.sweep_count)
            .finish()
    }
}

impl FakeWebBrowserProfileStore {
    /// Build a Fake store. Empty / whitespace roots and root collision fail closed.
    pub fn new(web_root: impl Into<PathBuf>, bitwarden_root: impl Into<PathBuf>) -> Result<Self, HttpError> {
        let web_root = web_root.into();
        let bitwarden_root = bitwarden_root.into();
        require_non_empty_path(&web_root)?;
        require_non_empty_path(&bitwarden_root)?;
        if path_eq_ignore_case(&web_root, &bitwarden_root) {
            return Err(HttpError::WebProfileRootCollision);
        }
        Ok(Self {
            web_root,
            bitwarden_root,
            web_folders: BTreeSet::new(),
            bitwarden_folders: BTreeSet::new(),
            wipe_count: 0,
            sweep_count: 0,
        })
    }

    pub fn web_root(&self) -> &Path {
        &self.web_root
    }

    pub fn bitwarden_root(&self) -> &Path {
        &self.bitwarden_root
    }

    pub fn wipe_count(&self) -> usize {
        self.wipe_count
    }

    pub fn sweep_count(&self) -> usize {
        self.sweep_count
    }

    pub fn web_folder_count(&self) -> usize {
        self.web_folders.len()
    }

    pub fn bitwarden_folder_count(&self) -> usize {
        self.bitwarden_folders.len()
    }

    pub fn contains_web_folder(&self, name: &str) -> bool {
        self.web_folders.contains(name)
    }

    pub fn contains_bitwarden_folder(&self, name: &str) -> bool {
        self.bitwarden_folders.contains(name)
    }

    /// Seed a single-segment folder name under the web root (fail-closed empty / hostile).
    pub fn seed_web_folder(&mut self, name: &str) -> Result<(), HttpError> {
        let name = require_folder_name(name)?;
        self.web_folders.insert(name);
        Ok(())
    }

    /// Seed a Bitwarden profile folder (survives [`Self::clear_web_browser_user_data`]).
    pub fn seed_bitwarden_folder(&mut self, name: &str) -> Result<(), HttpError> {
        let name = require_folder_name(name)?;
        self.bitwarden_folders.insert(name);
        Ok(())
    }

    /// Fake `App.ClearWebBrowserUserData` — wipe all tracked web folders; leave Bitwarden.
    pub fn clear_web_browser_user_data(&mut self) -> WebBrowserWipeReport {
        let removed = self.web_folders.len();
        let was_empty = removed == 0;
        self.web_folders.clear();
        self.wipe_count = self.wipe_count.saturating_add(1);
        WebBrowserWipeReport { removed, was_empty }
    }

    /// Fake `SweepStaleKeyedFolders` under the web root (keeps current fingerprint + non-shared).
    pub fn sweep_stale_keyed_folders(&mut self) -> usize {
        let current = keyed_shared_folder_name();
        let stale = stale_keyed_folder_names(self.web_folders.iter().map(String::as_str), &current);
        let removed = stale.len();
        for name in stale {
            self.web_folders.remove(&name);
        }
        self.sweep_count = self.sweep_count.saturating_add(1);
        removed
    }

    /// Resolve + record the folder for a target (seeds the Fake web set).
    pub fn resolve_and_seed_for_target(
        &mut self,
        target: &HttpConnectionTarget,
        isolated_id: &str,
    ) -> Result<PathBuf, HttpError> {
        let kind = select_web_browser_profile_kind(
            target.socks5_proxy,
            target.ignore_cert_errors(),
            isolated_id,
        )?;
        let (path, name) = match &kind {
            WebBrowserProfileKind::Shared => {
                require_non_empty_path(&self.web_root)?;
                let name = keyed_shared_folder_name();
                (self.web_root.join(&name), name)
            }
            // `id` already validated by `select_web_browser_profile_kind`.
            WebBrowserProfileKind::Isolated { id } => {
                require_non_empty_path(&self.web_root)?;
                (
                    self.web_root.join(format!("env-{id}")),
                    format!("env-{id}"),
                )
            }
        };
        self.seed_web_folder(&name)?;
        Ok(path)
    }
}

fn require_non_empty_path(path: &Path) -> Result<(), HttpError> {
    let s = path.as_os_str();
    if s.is_empty() {
        return Err(HttpError::EmptyPath);
    }
    // Whitespace-only OsStr (UTF-8), including Unicode White_Space (e.g. NBSP).
    if let Some(text) = path.to_str() {
        if text.trim().is_empty() {
            return Err(HttpError::EmptyPath);
        }
    }
    Ok(())
}

fn require_isolated_id(id: &str) -> Result<String, HttpError> {
    require_folder_name(id)
}

fn require_folder_name(name: &str) -> Result<String, HttpError> {
    let trimmed = name.trim();
    if trimmed.is_empty()
        || trimmed.contains('\0')
        || trimmed.contains('/')
        || trimmed.contains('\\')
        || trimmed == "."
        || trimmed == ".."
    {
        return Err(HttpError::EmptyIsolatedId);
    }
    if Path::new(trimmed).components().count() != 1 {
        return Err(HttpError::EmptyIsolatedId);
    }
    Ok(trimmed.to_string())
}

fn path_eq_ignore_case(a: &Path, b: &Path) -> bool {
    match (a.to_str(), b.to_str()) {
        (Some(a), Some(b)) => a.eq_ignore_ascii_case(b),
        _ => a == b,
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0xf) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::target::{
        build_direct_target, build_socks_target, HttpCertPolicy, HttpScheme,
    };

    #[test]
    fn keyed_shared_folder_name_is_stable_hardening_fingerprint() {
        let name = keyed_shared_folder_name();
        assert_eq!(name, "shared-815e5671");
        assert_eq!(name, keyed_shared_folder_name());
        assert_eq!(
            keyed_shared_folder_fingerprint_args(),
            HARDENING_BROWSER_ARGS
        );
    }

    #[test]
    fn isolation_triggers_on_socks_or_ignore_cert() {
        assert!(!requires_isolated_web_profile(None, false));
        assert!(requires_isolated_web_profile(None, true));
        let socks = Socks5Proxy::loopback(1080).unwrap();
        assert!(requires_isolated_web_profile(Some(socks), false));
        assert!(requires_isolated_web_profile(Some(socks), true));
    }

    #[test]
    fn plain_http_leaf_ignore_does_not_isolate_via_target() {
        // C#: IgnoreCertErrors is scheme-gated; HTTP leaf flag must not force isolation.
        let http = build_direct_target(HttpScheme::Http, "router.example", 80, true).unwrap();
        assert_eq!(http.cert_policy, HttpCertPolicy::Default);
        assert!(!target_requires_isolated_web_profile(&http));
        let root = Path::new(r"C:\Wormhole\webview2-web");
        let path =
            select_web_browser_user_data_folder_for_target(root, &http, "").unwrap();
        assert_eq!(path, root.join(keyed_shared_folder_name()));
        assert!(matches!(
            select_web_browser_profile_kind(None, false, "").unwrap(),
            WebBrowserProfileKind::Shared
        ));
    }

    #[test]
    fn shared_and_isolated_paths_join_under_root() {
        let root = Path::new(r"C:\Wormhole\webview2-web");
        let shared = web_browser_shared_user_data(root).unwrap();
        assert_eq!(shared, root.join("shared-815e5671"));
        let iso = web_browser_isolated_user_data(root, "abc123").unwrap();
        assert_eq!(iso, root.join("env-abc123"));
    }

    #[test]
    fn empty_paths_and_ids_fail_closed() {
        assert_eq!(
            web_browser_shared_user_data(Path::new("")).unwrap_err(),
            HttpError::EmptyPath
        );
        assert_eq!(
            web_browser_shared_user_data(Path::new("   ")).unwrap_err(),
            HttpError::EmptyPath
        );
        assert_eq!(
            web_browser_shared_user_data(Path::new("\u{00a0}")).unwrap_err(),
            HttpError::EmptyPath
        );
        assert_eq!(
            web_browser_isolated_user_data(Path::new(r"C:\web"), "").unwrap_err(),
            HttpError::EmptyIsolatedId
        );
        assert_eq!(
            web_browser_isolated_user_data(Path::new(r"C:\web"), "  ").unwrap_err(),
            HttpError::EmptyIsolatedId
        );
        assert_eq!(
            web_browser_isolated_user_data(Path::new(r"C:\web"), "\u{00a0}").unwrap_err(),
            HttpError::EmptyIsolatedId
        );
        assert_eq!(
            web_browser_isolated_user_data(Path::new(r"C:\web"), r"..\x").unwrap_err(),
            HttpError::EmptyIsolatedId
        );
        assert_eq!(
            select_web_browser_profile_kind(None, true, "").unwrap_err(),
            HttpError::EmptyIsolatedId
        );
    }

    #[test]
    fn select_folder_matches_view_rules() {
        let root = Path::new(r"C:\Wormhole\webview2-web");
        let plain = select_web_browser_user_data_folder(root, None, false, "unused").unwrap();
        assert_eq!(plain, root.join(keyed_shared_folder_name()));

        let socks = Socks5Proxy::loopback(9).unwrap();
        let proxied =
            select_web_browser_user_data_folder(root, Some(socks), false, "deadbeef").unwrap();
        assert_eq!(proxied, root.join("env-deadbeef"));

        let ignore =
            select_web_browser_user_data_folder(root, None, true, "cafebabe").unwrap();
        assert_eq!(ignore, root.join("env-cafebabe"));
    }

    #[test]
    fn target_overload_uses_resolved_cert_and_socks() {
        let root = Path::new(r"C:\Wormhole\webview2-web");
        let direct = build_direct_target(
            HttpScheme::Https,
            "router.example",
            443,
            true, // leaf ignore → IgnoreErrors on HTTPS
        )
        .unwrap();
        assert_eq!(direct.cert_policy, HttpCertPolicy::IgnoreErrors);
        let path =
            select_web_browser_user_data_folder_for_target(root, &direct, "iso1").unwrap();
        assert_eq!(path, root.join("env-iso1"));
        assert!(target_requires_isolated_web_profile(&direct));

        let socks = build_socks_target(
            HttpScheme::Http,
            "router.example",
            80,
            false,
            Socks5Proxy::loopback(1080).unwrap(),
            None,
        )
        .unwrap();
        assert!(!socks.ignore_cert_errors());
        let path =
            select_web_browser_user_data_folder_for_target(root, &socks, "iso2").unwrap();
        assert_eq!(path, root.join("env-iso2"));
    }

    #[test]
    fn fake_wipe_clears_web_not_bitwarden() {
        let mut store =
            FakeWebBrowserProfileStore::new(r"C:\Wormhole\webview2-web", r"C:\Wormhole\bw")
                .unwrap();
        store.seed_web_folder(&keyed_shared_folder_name()).unwrap();
        store.seed_web_folder("env-aaaa").unwrap();
        store.seed_web_folder("shared-deadbeef").unwrap();
        store.seed_bitwarden_folder("profile-abc").unwrap();

        let report = store.clear_web_browser_user_data();
        assert_eq!(report.removed, 3);
        assert!(!report.was_empty);
        assert_eq!(store.web_folder_count(), 0);
        assert_eq!(store.bitwarden_folder_count(), 1);
        assert!(store.contains_bitwarden_folder("profile-abc"));
        assert_eq!(store.wipe_count(), 1);

        let empty = store.clear_web_browser_user_data();
        assert!(empty.was_empty);
        assert_eq!(empty.removed, 0);
        assert_eq!(store.wipe_count(), 2);
        assert!(store.contains_bitwarden_folder("profile-abc"));
    }

    #[test]
    fn fake_store_rejects_empty_and_colliding_roots() {
        assert_eq!(
            FakeWebBrowserProfileStore::new("", r"C:\bw").unwrap_err(),
            HttpError::EmptyPath
        );
        assert_eq!(
            FakeWebBrowserProfileStore::new(r"C:\web", "   ").unwrap_err(),
            HttpError::EmptyPath
        );
        assert_eq!(
            FakeWebBrowserProfileStore::new("\u{00a0}", r"C:\bw").unwrap_err(),
            HttpError::EmptyPath
        );
        assert_eq!(
            FakeWebBrowserProfileStore::new(r"C:\same", r"C:\same").unwrap_err(),
            HttpError::WebProfileRootCollision
        );
        assert_eq!(
            FakeWebBrowserProfileStore::new(r"C:\Same", r"c:\same").unwrap_err(),
            HttpError::WebProfileRootCollision
        );
    }

    #[test]
    fn sweep_removes_stale_shared_keeps_current_and_env() {
        let mut store =
            FakeWebBrowserProfileStore::new(r"C:\Wormhole\webview2-web", r"C:\Wormhole\bw")
                .unwrap();
        let current = keyed_shared_folder_name();
        store.seed_web_folder(&current).unwrap();
        store.seed_web_folder("shared-deadbeef").unwrap();
        store.seed_web_folder("env-1234").unwrap();

        let removed = store.sweep_stale_keyed_folders();
        assert_eq!(removed, 1);
        assert!(store.contains_web_folder(&current));
        assert!(!store.contains_web_folder("shared-deadbeef"));
        assert!(store.contains_web_folder("env-1234"));
        assert_eq!(store.sweep_count(), 1);
    }

    #[test]
    fn stale_keyed_helper_is_case_insensitive_on_current() {
        let current = keyed_shared_folder_name();
        let upper = current.to_ascii_uppercase();
        let stale = stale_keyed_folder_names(
            [upper.as_str(), "shared-deadbeef", "env-1", "profile-x"],
            &current,
        );
        assert_eq!(stale, vec!["shared-deadbeef".to_string()]);
        assert!(stale_keyed_folder_names(["shared-deadbeef"], "").is_empty());
        assert!(stale_keyed_folder_names(["shared-deadbeef"], "   ").is_empty());
        // Non-shared keep name must not mass-delete every shared-* entry.
        assert!(stale_keyed_folder_names(["shared-deadbeef", &current], "env-1").is_empty());
        // Padded fingerprint must still keep the real current folder.
        let padded = format!("  {current}  ");
        assert_eq!(
            stale_keyed_folder_names(
                [current.as_str(), "shared-deadbeef", "env-1"],
                &padded,
            ),
            vec!["shared-deadbeef".to_string()]
        );
    }

    #[test]
    fn wipe_leaves_bitwarden_even_when_folder_names_collide() {
        let mut store =
            FakeWebBrowserProfileStore::new(r"C:\Wormhole\webview2-web", r"C:\Wormhole\bw")
                .unwrap();
        store.seed_web_folder("profile-abc").unwrap();
        store.seed_bitwarden_folder("profile-abc").unwrap();
        let report = store.clear_web_browser_user_data();
        assert_eq!(report.removed, 1);
        assert!(!store.contains_web_folder("profile-abc"));
        assert!(store.contains_bitwarden_folder("profile-abc"));
    }

    #[test]
    fn debug_redacts_ids_and_paths() {
        let kind = WebBrowserProfileKind::Isolated {
            id: "super-secret-guid".into(),
        };
        let dbg = format!("{kind:?}");
        assert!(dbg.contains("id_len"));
        assert!(!dbg.contains("super-secret-guid"));

        let store =
            FakeWebBrowserProfileStore::new(r"C:\Wormhole\webview2-web", r"C:\Wormhole\bw")
                .unwrap();
        let dbg = format!("{store:?}");
        assert!(dbg.contains("web_root_len"));
        assert!(!dbg.contains(r"C:\Wormhole"));
    }

    #[test]
    fn resolve_and_seed_records_shared_or_isolated() {
        let mut store =
            FakeWebBrowserProfileStore::new(r"C:\Wormhole\webview2-web", r"C:\Wormhole\bw")
                .unwrap();
        let plain = build_direct_target(HttpScheme::Http, "h", 80, false).unwrap();
        let path = store.resolve_and_seed_for_target(&plain, "ignored").unwrap();
        assert!(path.ends_with(keyed_shared_folder_name()));
        assert!(store.contains_web_folder(&keyed_shared_folder_name()));

        // SOCKS / ignore-cert must seed env-<id>; empty id fails closed (no mutation).
        let socks = build_socks_target(
            HttpScheme::Https,
            "h",
            443,
            false,
            Socks5Proxy::loopback(1080).unwrap(),
            None,
        )
        .unwrap();
        let before = store.web_folder_count();
        assert_eq!(
            store
                .resolve_and_seed_for_target(&socks, "")
                .unwrap_err(),
            HttpError::EmptyIsolatedId
        );
        assert_eq!(store.web_folder_count(), before);

        let iso = store
            .resolve_and_seed_for_target(&socks, "deadbeef01")
            .unwrap();
        assert_eq!(iso, store.web_root().join("env-deadbeef01"));
        assert!(store.contains_web_folder("env-deadbeef01"));

        let ignore = build_direct_target(HttpScheme::Https, "h", 443, true).unwrap();
        assert!(ignore.ignore_cert_errors());
        let iso2 = store
            .resolve_and_seed_for_target(&ignore, "cafebabe02")
            .unwrap();
        assert_eq!(iso2, store.web_root().join("env-cafebabe02"));
        assert!(store.contains_web_folder("env-cafebabe02"));
    }

    #[test]
    fn seed_rejects_hostile_folder_names() {
        let mut store =
            FakeWebBrowserProfileStore::new(r"C:\Wormhole\webview2-web", r"C:\Wormhole\bw")
                .unwrap();
        for bad in ["", "  ", "\u{00a0}", "..", ".", r"a\b", "a/b", "x\0y"] {
            assert_eq!(
                store.seed_web_folder(bad).unwrap_err(),
                HttpError::EmptyIsolatedId,
                "web seed {bad:?}"
            );
            assert_eq!(
                store.seed_bitwarden_folder(bad).unwrap_err(),
                HttpError::EmptyIsolatedId,
                "bw seed {bad:?}"
            );
        }
        assert_eq!(store.web_folder_count(), 0);
        assert_eq!(store.bitwarden_folder_count(), 0);
    }

    #[test]
    fn sweep_never_touches_bitwarden_folders() {
        let mut store =
            FakeWebBrowserProfileStore::new(r"C:\Wormhole\webview2-web", r"C:\Wormhole\bw")
                .unwrap();
        store.seed_web_folder("shared-deadbeef").unwrap();
        store.seed_bitwarden_folder("shared-deadbeef").unwrap();
        store.seed_bitwarden_folder(&keyed_shared_folder_name()).unwrap();
        let removed = store.sweep_stale_keyed_folders();
        assert_eq!(removed, 1);
        assert!(!store.contains_web_folder("shared-deadbeef"));
        assert!(store.contains_bitwarden_folder("shared-deadbeef"));
        assert!(store.contains_bitwarden_folder(&keyed_shared_folder_name()));
        assert_eq!(store.bitwarden_folder_count(), 2);
    }

    #[test]
    fn wipe_then_reseed_shared_is_idempotent_lifecycle() {
        let mut store =
            FakeWebBrowserProfileStore::new(r"C:\Wormhole\webview2-web", r"C:\Wormhole\bw")
                .unwrap();
        let plain = build_direct_target(HttpScheme::Https, "a", 443, false).unwrap();
        store.resolve_and_seed_for_target(&plain, "").unwrap();
        assert_eq!(store.web_folder_count(), 1);
        store.clear_web_browser_user_data();
        assert_eq!(store.web_folder_count(), 0);
        store.resolve_and_seed_for_target(&plain, "").unwrap();
        assert!(store.contains_web_folder(&keyed_shared_folder_name()));
        assert_eq!(store.bitwarden_folder_count(), 0);
    }
}
