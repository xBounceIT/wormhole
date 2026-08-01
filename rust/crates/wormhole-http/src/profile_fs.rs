//! Real + Fake filesystem seam for the regular (non-Bitwarden) web-browser
//! WebView2 user-data **wipe** and env-args directory glue.
//!
//! Ports the actual-disk application of:
//! - `App.ClearWebBrowserUserData` (startup wipe of `webview2-web\`)
//! - `WebViewBrowserArguments.SweepStaleKeyedFolders` (stale `shared-*` siblings)
//! - `AppPaths.GetWebBrowserSharedUserDataDirectory` /
//!   `GetWebBrowserIsolatedUserDataDirectory` (args → directory application)
//!
//! The fingerprint / profile-kind *selection* logic stays in [`crate::profile_wipe`];
//! this module is the injectable-FS execution site. WebView2 *environment creation*
//! itself is **Pending** (no COM here): [`ProfileWipeGlue::ensure_web_browser_user_data_dir`]
//! covers the create-dir part only.
//!
//! [`RealProfileFs`] is a thin `std::fs` adapter; [`FakeProfileFs`] is an in-memory map
//! confined to a base root so unit tests never touch real user folders
//! (zip-slip-style confinement mirrored from the extension `FakeExtensionInstallFs`).
//! HTTP(S) is credential-less: [`Debug`] shows path lengths and entry counts only.
//!
//! | Guard | Result |
//! |---|---|
//! | empty / whitespace `web_root` | [`HttpError::EmptyPath`] — no IO (constructor) |
//! | `bitwarden_root` equal to / nested under `web_root` (or vice versa, after `.`-folding) | [`HttpError::WebProfileRootCollision`] — no IO (constructor) |
//! | `web_root` / child with `..`, absolute escape, or empty | [`HttpError::UnsafeProfilePath`] — rejected **before any IO** |
//! | locked file / any remove IO error mid-wipe | swallowed into `failed`; remaining entries still wiped (C# `catch` + continue) |
//! | sweep enumeration failure | tolerated no-op (C# swallows; stale folders cost disk space, not correctness) |
//! | web root missing | idempotent no-op (`was_empty = true`) |

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex};

use crate::profile_wipe::{
    keyed_shared_folder_name, select_web_browser_user_data_folder, stale_keyed_folder_names,
};
use crate::target::Socks5Proxy;
use crate::HttpError;

/// Errors surfaced by a [`ProfileFs`] implementation.
///
/// Message strings never embed paths, file bytes, or credentials.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProfileFsError {
    /// A candidate path escaped the allowed root (`..`, absolute, empty).
    #[error("web profile filesystem path escaped the allowed root")]
    PathNotConfined,
    /// The requested entry does not exist.
    #[error("web profile filesystem entry not found")]
    NotFound,
    /// The underlying IO operation failed (e.g. a locked browser file).
    #[error("web profile filesystem operation failed")]
    Io,
}

/// Injectable filesystem for web-profile wipe / env-args glue (real disk or Fake map).
///
/// Mirrors the extension `ExtensionInstallFs` style: by-reference methods so
/// implementations can share interior state, `Send + Sync` so a host can run the
/// wipe off the UI thread.
pub trait ProfileFs: Send + Sync {
    /// Whether `path` exists and is a directory (or has descendants).
    fn is_dir(&self, path: &Path) -> bool;
    /// Direct children of `path` (absolute, sorted). Missing root → empty or error.
    fn list_dir(&self, path: &Path) -> Result<Vec<PathBuf>, ProfileFsError>;
    /// Create `path` and any missing parents.
    fn create_dir_all(&self, path: &Path) -> Result<(), ProfileFsError>;
    /// Read the full contents of `path`.
    fn read_file(&self, path: &Path) -> Result<Vec<u8>, ProfileFsError>;
    /// Remove a regular file at `path`.
    fn remove_file(&self, path: &Path) -> Result<(), ProfileFsError>;
    /// Recursively remove the directory tree at `path` (fails when the directory
    /// itself or a file under it is locked — mirrors `std::fs::remove_dir_all`
    /// on Windows).
    fn remove_dir_all(&self, path: &Path) -> Result<(), ProfileFsError>;
}

/// Real-disk [`ProfileFs`] backed by `std::fs`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RealProfileFs;

impl ProfileFs for RealProfileFs {
    fn is_dir(&self, path: &Path) -> bool {
        path.is_dir()
    }

    fn list_dir(&self, path: &Path) -> Result<Vec<PathBuf>, ProfileFsError> {
        let mut out = Vec::new();
        for entry in std::fs::read_dir(path).map_err(|_| ProfileFsError::Io)? {
            out.push(entry.map_err(|_| ProfileFsError::Io)?.path());
        }
        out.sort();
        Ok(out)
    }

    fn create_dir_all(&self, path: &Path) -> Result<(), ProfileFsError> {
        std::fs::create_dir_all(path).map_err(|_| ProfileFsError::Io)
    }

    fn read_file(&self, path: &Path) -> Result<Vec<u8>, ProfileFsError> {
        std::fs::read(path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                ProfileFsError::NotFound
            } else {
                ProfileFsError::Io
            }
        })
    }

    fn remove_file(&self, path: &Path) -> Result<(), ProfileFsError> {
        std::fs::remove_file(path).map_err(|_| ProfileFsError::Io)
    }

    fn remove_dir_all(&self, path: &Path) -> Result<(), ProfileFsError> {
        std::fs::remove_dir_all(path).map_err(|_| ProfileFsError::Io)
    }
}

/// Outcome of a real / best-effort web-profile wipe.
#[derive(Clone, PartialEq, Eq)]
pub struct ProfileWipeReport {
    /// Top-level entries fully removed under the web root.
    pub removed: usize,
    /// True when the root held no entries (idempotent no-op — missing or empty root).
    pub was_empty: bool,
    /// Entries whose removal was swallowed (locked file / IO, per C# `catch` + continue).
    pub failed: usize,
}

impl fmt::Debug for ProfileWipeReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProfileWipeReport")
            .field("removed", &self.removed)
            .field("was_empty", &self.was_empty)
            .field("failed", &self.failed)
            .finish()
    }
}

/// In-memory [`ProfileFs`] confined to a base root — never touches real disk.
///
/// Nodes are stored in a map keyed by normalized (prefix/root-curDir-folded,
/// `..`-rejected) paths. Every operation goes through confinement, so a hostile
/// `..` / absolute / empty path returns [`ProfileFsError::PathNotConfined`]
/// without mutating anything (zip-slip-style, like the extension `FakeExtensionInstallFs`).
/// A "locked" file (see [`Self::lock_file`]) models a Windows-shared-lock that makes
/// removal fail while reads still work.
#[derive(Clone)]
pub struct FakeProfileFs {
    base_root: PathBuf,
    inner: Arc<Mutex<FakeProfileFsInner>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum FakeProfileNode {
    Dir,
    File(Vec<u8>),
}

#[derive(Debug, Clone, Default)]
struct FakeProfileFsInner {
    nodes: BTreeMap<PathBuf, FakeProfileNode>,
    locked: BTreeSet<PathBuf>,
}

impl fmt::Debug for FakeProfileFs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let inner = self.inner.lock().unwrap();
        f.debug_struct("FakeProfileFs")
            .field("base_root_len", &self.base_root.as_os_str().len())
            .field("entry_count", &inner.nodes.len())
            .field("locked_count", &inner.locked.len())
            .finish()
    }
}

impl FakeProfileFs {
    /// Empty Fake tree confined under `base_root`. Empty `base_root` fails closed.
    pub fn new(base_root: impl Into<PathBuf>) -> Result<Self, HttpError> {
        let base_root = base_root.into();
        require_non_empty_path(&base_root)?;
        if has_parent_dir(&base_root) {
            return Err(HttpError::UnsafeProfilePath);
        }
        Ok(Self {
            base_root,
            inner: Arc::new(Mutex::new(FakeProfileFsInner::default())),
        })
    }

    /// Base root this Fake is confined to.
    pub fn base_root(&self) -> &Path {
        &self.base_root
    }

    /// Seed a directory marker (rejects paths that escape the base root).
    pub fn seed_dir(&self, path: impl Into<PathBuf>) -> Result<(), ProfileFsError> {
        let path = self.confine_node(path.into())?;
        self.inner.lock().unwrap().nodes.insert(path, FakeProfileNode::Dir);
        Ok(())
    }

    /// Seed a file (creates parent dir markers; rejects escape paths).
    pub fn seed_file(&self, path: impl Into<PathBuf>, content: impl Into<Vec<u8>>) -> Result<(), ProfileFsError> {
        let path = self.confine_node(path.into())?;
        self.create_dir_all(&path)?;
        self.inner
            .lock()
            .unwrap()
            .nodes
            .insert(path, FakeProfileNode::File(content.into()));
        Ok(())
    }

    /// Mark a seeded file as locked: removal (file or containing tree) fails with
    /// [`ProfileFsError::Io`], modeling a Windows-sharing lock (ERROR_INVALID_STATE-ish).
    pub fn lock_file(&self, path: impl Into<PathBuf>) -> Result<(), ProfileFsError> {
        let path = self.confine_node(path.into())?;
        self.inner.lock().unwrap().locked.insert(path);
        Ok(())
    }

    /// Whether a file or dir node exists at `path`.
    pub fn contains(&self, path: impl Into<PathBuf>) -> bool {
        let Ok(path) = self.confine_node(path.into()) else {
            return false;
        };
        self.inner.lock().unwrap().nodes.contains_key(&path)
    }

    /// Whether a file node exists at `path` (and is not a dir).
    pub fn contains_file(&self, path: impl Into<PathBuf>) -> bool {
        let Ok(path) = self.confine_node(path.into()) else {
            return false;
        };
        matches!(
            self.inner.lock().unwrap().nodes.get(&path),
            Some(FakeProfileNode::File(_))
        )
    }

    /// Whether a directory node (or dir-with-descendants) exists at `path`.
    pub fn contains_dir(&self, path: impl Into<PathBuf>) -> bool {
        let Ok(path) = self.confine_node(path.into()) else {
            return false;
        };
        let inner = self.inner.lock().unwrap();
        matches!(inner.nodes.get(&path), Some(FakeProfileNode::Dir))
            || inner.nodes.keys().any(|p| p.starts_with(&path))
    }

    /// Read a seeded file back for assertions.
    pub fn read_seeded(&self, path: impl Into<PathBuf>) -> Result<Vec<u8>, ProfileFsError> {
        self.read_file(&self.confine_node(path.into())?)
    }

    fn confine_node(&self, path: PathBuf) -> Result<PathBuf, ProfileFsError> {
        confined_fake_node(&self.base_root, &path)
    }
}

impl ProfileFs for FakeProfileFs {
    fn is_dir(&self, path: &Path) -> bool {
        let Ok(path) = self.confine_node(path.to_path_buf()) else {
            return false;
        };
        let inner = self.inner.lock().unwrap();
        matches!(inner.nodes.get(&path), Some(FakeProfileNode::Dir))
            || inner.nodes.keys().any(|p| p.starts_with(&path))
    }

    fn list_dir(&self, path: &Path) -> Result<Vec<PathBuf>, ProfileFsError> {
        let path = self.confine_node(path.to_path_buf())?;
        let inner = self.inner.lock().unwrap();
        let mut out: Vec<PathBuf> = inner
            .nodes
            .keys()
            .filter(|p| {
                if let Ok(rel) = p.strip_prefix(&path) {
                    !rel.as_os_str().is_empty() && rel.components().count() == 1
                } else {
                    false
                }
            })
            .cloned()
            .collect();
        out.sort();
        Ok(out)
    }

    fn create_dir_all(&self, path: &Path) -> Result<(), ProfileFsError> {
        let path = self.confine_node(path.to_path_buf())?;
        let mut inner = self.inner.lock().unwrap();
        let mut acc = PathBuf::new();
        for comp in path.components() {
            acc.push(comp.as_os_str());
            inner.nodes.insert(acc.clone(), FakeProfileNode::Dir);
        }
        Ok(())
    }

    fn read_file(&self, path: &Path) -> Result<Vec<u8>, ProfileFsError> {
        let path = self.confine_node(path.to_path_buf())?;
        match self.inner.lock().unwrap().nodes.get(&path) {
            Some(FakeProfileNode::File(bytes)) => Ok(bytes.clone()),
            _ => Err(ProfileFsError::NotFound),
        }
    }

    fn remove_file(&self, path: &Path) -> Result<(), ProfileFsError> {
        let path = self.confine_node(path.to_path_buf())?;
        let mut inner = self.inner.lock().unwrap();
        if inner.locked.contains(&path) {
            return Err(ProfileFsError::Io);
        }
        match inner.nodes.remove(&path) {
            Some(FakeProfileNode::File(_)) => Ok(()),
            Some(FakeProfileNode::Dir) => Err(ProfileFsError::Io),
            None => Err(ProfileFsError::NotFound),
        }
    }

    fn remove_dir_all(&self, path: &Path) -> Result<(), ProfileFsError> {
        let path = self.confine_node(path.to_path_buf())?;
        let mut inner = self.inner.lock().unwrap();
        if inner.locked.iter().any(|locked| locked.starts_with(&path)) {
            return Err(ProfileFsError::Io);
        }
        inner.nodes.retain(|p, _| p != &path && !p.starts_with(&path));
        inner.locked.retain(|p| !p.starts_with(&path));
        Ok(())
    }
}

/// Lexically confine `path` under `base`, rejecting `..` / absolute / empty escapes.
///
/// Returns a rebuilt, CurDir-normalized path (prefix + root kept so sibling
/// absolute roots do not collide). Used by [`FakeProfileFs`] for its map keys and
/// fail-closed tests.
pub(crate) fn confined_fake_node(base: &Path, path: &Path) -> Result<PathBuf, ProfileFsError> {
    if base.as_os_str().is_empty()
        || path.as_os_str().is_empty()
        || has_parent_dir(base)
        || has_parent_dir(path)
    {
        return Err(ProfileFsError::PathNotConfined);
    }
    confined_under(base, path).ok_or(ProfileFsError::PathNotConfined)
}

/// Confine a web-profile path under `web_root` (fail closed → [`HttpError::UnsafeProfilePath`]).
///
/// Empty root → [`HttpError::EmptyPath`]. Rejected **before any IO** on escape.
pub fn confine_profile_path(web_root: &Path, path: &Path) -> Result<PathBuf, HttpError> {
    require_non_empty_path(web_root)?;
    if path.as_os_str().is_empty() || has_parent_dir(web_root) || has_parent_dir(path) {
        return Err(HttpError::UnsafeProfilePath);
    }
    confined_under(web_root, path).ok_or(HttpError::UnsafeProfilePath)
}

/// Shared confinement core: returns the CurDir-folded `path` when it stays under
/// `base`. The emptiness / parent-dir guards and error mapping live in the two
/// public wrappers so the one security-critical prefix decision is never forked.
fn confined_under(base: &Path, path: &Path) -> Option<PathBuf> {
    let normalized = normalize_cur_dir(path);
    normalized
        .starts_with(normalize_cur_dir(base))
        .then_some(normalized)
}

/// Composition: runs the real wipe / env-args directory application against an
/// injectable [`ProfileFs`]. Fingerprint selection stays in [`crate::profile_wipe`].
#[derive(Clone, PartialEq, Eq)]
pub struct ProfileWipeGlue<F> {
    web_root: PathBuf,
    bitwarden_root: PathBuf,
    fs: F,
}

impl<F: fmt::Debug> fmt::Debug for ProfileWipeGlue<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProfileWipeGlue")
            .field("web_root_len", &self.web_root.as_os_str().len())
            .field("bitwarden_root_len", &self.bitwarden_root.as_os_str().len())
            .field("fs", &self.fs)
            .finish()
    }
}

impl<F: ProfileFs> ProfileWipeGlue<F> {
    /// New glue over `fs` with `web_root` (wipe target) and `bitwarden_root`
    /// (never wiped). Validates all fail-closed guards up front — no IO.
    pub fn new(
        fs: F,
        web_root: impl Into<PathBuf>,
        bitwarden_root: impl Into<PathBuf>,
    ) -> Result<Self, HttpError> {
        let web_root = web_root.into();
        let bitwarden_root = bitwarden_root.into();
        require_non_empty_path(&web_root)?;
        require_non_empty_path(&bitwarden_root)?;
        if has_parent_dir(&web_root) || has_parent_dir(&bitwarden_root) {
            return Err(HttpError::UnsafeProfilePath);
        }
        if roots_overlap(&web_root, &bitwarden_root) {
            return Err(HttpError::WebProfileRootCollision);
        }
        Ok(Self {
            web_root,
            bitwarden_root,
            fs,
        })
    }

    /// Web root (`webview2-web\`) — wiped, never Bitwarden.
    pub fn web_root(&self) -> &Path {
        &self.web_root
    }

    /// Persistent Bitwarden extension root — never wiped.
    pub fn bitwarden_root(&self) -> &Path {
        &self.bitwarden_root
    }

    /// Real `App.ClearWebBrowserUserData` over `web_root`: remove every top-level
    /// entry (the fingerprinted `shared-*` and per-tab `env-<id>` folders). The
    /// Bitwarden extension root is never touched.
    ///
    /// Hostile entry paths fail the call closed (nothing removed). Runtime remove
    /// errors (e.g. a locked browser file) are swallowed into `failed` and the
    /// remaining entries are still wiped — C# `catch` + continue parity.
    pub fn wipe_web_browser_user_data(&self) -> Result<ProfileWipeReport, HttpError> {
        if !self.fs.is_dir(&self.web_root) {
            return Ok(ProfileWipeReport {
                removed: 0,
                was_empty: true,
                failed: 0,
            });
        }
        let entries = match self.fs.list_dir(&self.web_root) {
            Ok(entries) => entries,
            // Enumeration failure is tolerated (C# swallows it): report the root as failed.
            Err(_) => {
                return Ok(ProfileWipeReport {
                    removed: 0,
                    was_empty: false,
                    failed: 1,
                })
            }
        };
        let was_empty = entries.is_empty();
        // Fail closed before any IO: every entry must stay under web_root.
        for entry in &entries {
            confine_profile_path(&self.web_root, entry)?;
        }
        let mut removed = 0usize;
        let mut failed = 0usize;
        for entry in entries {
            let result = if self.fs.is_dir(&entry) {
                self.fs.remove_dir_all(&entry)
            } else {
                self.fs.remove_file(&entry)
            };
            match result {
                Ok(()) => removed = removed.saturating_add(1),
                Err(_) => failed = failed.saturating_add(1),
            }
        }
        Ok(ProfileWipeReport {
            removed,
            was_empty,
            failed,
        })
    }

    /// Real `WebViewBrowserArguments.SweepStaleKeyedFolders`: remove `shared-*`
    /// siblings of the current fingerprint under `web_root`; keep the current
    /// case-insensitive match, `env-*` isolated folders, and non-`shared-*` folders.
    ///
    /// Returns how many stale folders were actually removed. A folder locked by a
    /// still-running older build is skipped (swallowed), matching the C# per-dir
    /// `catch`; an enumeration failure is a tolerated no-op (C# swallows it);
    /// hostile entries fail the call closed before any IO.
    pub fn sweep_stale_keyed_folders(&self) -> Result<usize, HttpError> {
        if !self.fs.is_dir(&self.web_root) {
            return Ok(0);
        }
        let entries = match self.fs.list_dir(&self.web_root) {
            Ok(entries) => entries,
            // Enumeration failure is tolerated (C# swallows it): stale folders
            // cost disk space, not correctness — report nothing swept.
            Err(_) => return Ok(0),
        };
        let current = keyed_shared_folder_name();
        let names: Vec<String> = entries
            .iter()
            .filter_map(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
            .collect();
        let stale = stale_keyed_folder_names(names.iter().map(String::as_str), &current);
        // Fail closed before any IO on hostile entries referenced by stale selection.
        for entry in &entries {
            confine_profile_path(&self.web_root, entry)?;
        }
        let by_name = |entry: &Path| entry.file_name().map(|n| n.to_string_lossy().into_owned());
        let targets: Vec<&Path> = entries
            .iter()
            .map(PathBuf::as_path)
            .filter(|entry| {
                by_name(entry)
                    .as_deref()
                    .map(|n| stale.iter().any(|s| s == n))
                    .unwrap_or(false)
            })
            .collect();
        let mut removed = 0usize;
        for entry in targets {
            if self.fs.is_dir(entry)
                && self.fs.remove_dir_all(entry).is_ok()
            {
                removed = removed.saturating_add(1);
            }
        }
        Ok(removed)
    }

    /// Resolve the argument-fingerprinted shared folder under `web_root` (no IO).
    pub fn web_browser_shared_dir(&self) -> Result<PathBuf, HttpError> {
        let path = crate::profile_wipe::web_browser_shared_user_data(&self.web_root)?;
        confine_profile_path(&self.web_root, &path)
    }

    /// Resolve the `env-<id>` isolated folder under `web_root` (no IO).
    pub fn web_browser_isolated_dir(&self, isolated_id: &str) -> Result<PathBuf, HttpError> {
        let path = crate::profile_wipe::web_browser_isolated_user_data(&self.web_root, isolated_id)?;
        confine_profile_path(&self.web_root, &path)
    }

    /// Args → directory application: resolve the folder for a regular web tab and
    /// create it (the create-dir part of WebView2 env creation; the environment
    /// itself is **Pending** / out of scope).
    pub fn ensure_web_browser_user_data_dir(
        &self,
        socks5: Option<Socks5Proxy>,
        ignore_cert_errors: bool,
        isolated_id: &str,
    ) -> Result<PathBuf, HttpError> {
        let path = select_web_browser_user_data_folder(
            &self.web_root,
            socks5,
            ignore_cert_errors,
            isolated_id,
        )?;
        let path = confine_profile_path(&self.web_root, &path)?;
        self.fs.create_dir_all(&path)?;
        Ok(path)
    }
}

fn require_non_empty_path(path: &Path) -> Result<(), HttpError> {
    let s = path.as_os_str();
    if s.is_empty() {
        return Err(HttpError::EmptyPath);
    }
    if let Some(text) = path.to_str() {
        if text.trim().is_empty() {
            return Err(HttpError::EmptyPath);
        }
    }
    Ok(())
}

fn has_parent_dir(path: &Path) -> bool {
    path.components()
        .any(|c| matches!(c, Component::ParentDir))
}

/// CurDir-folded path with prefix/root retained; ParentDir is rejected upstream.
fn normalize_cur_dir(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for comp in path.components() {
        if let Component::CurDir = comp {
            continue;
        }
        out.push(comp.as_os_str());
    }
    out
}

fn path_lower(path: &Path) -> PathBuf {
    PathBuf::from(path.to_string_lossy().to_ascii_lowercase())
}

/// True when `a` and `b` are equal or one is nested under the other (case-insensitive).
///
/// Both sides are CurDir-folded first so `C:\web\.` and `C:\web\bitwarden` are
/// seen as nested exactly as the confinement check sees them — a `.` segment must
/// not smuggle a Bitwarden root under the wipe root.
fn roots_overlap(a: &Path, b: &Path) -> bool {
    let a = path_lower(&normalize_cur_dir(a));
    let b = path_lower(&normalize_cur_dir(b));
    a == b || {
        let (long, short) = if a.as_os_str().len() >= b.as_os_str().len() {
            (&a, &b)
        } else {
            (&b, &a)
        };
        long.starts_with(short)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::target::{build_direct_target, build_socks_target, HttpScheme};

    fn web_root() -> PathBuf {
        PathBuf::from(r"C:\Wormhole\webview2-web")
    }

    fn bw_root() -> PathBuf {
        PathBuf::from(r"C:\Wormhole\bitwarden-browser-webview2")
    }

    fn glue(fs: impl ProfileFs + 'static) -> ProfileWipeGlue<impl ProfileFs> {
        ProfileWipeGlue::new(fs, web_root(), bw_root()).unwrap()
    }

    /// Fake delegating to `inner` but injecting hostile extra entries into
    /// `list_dir` (models an on-disk name that must fail the wipe/sweep closed).
    struct HostileListDirFs {
        inner: FakeProfileFs,
        hostile_extra: Vec<PathBuf>,
    }

    impl ProfileFs for HostileListDirFs {
        fn is_dir(&self, path: &Path) -> bool {
            self.inner.is_dir(path)
        }
        fn list_dir(&self, path: &Path) -> Result<Vec<PathBuf>, ProfileFsError> {
            let mut out = self.inner.list_dir(path)?;
            out.extend(self.hostile_extra.iter().cloned());
            out.sort();
            Ok(out)
        }
        fn create_dir_all(&self, path: &Path) -> Result<(), ProfileFsError> {
            self.inner.create_dir_all(path)
        }
        fn read_file(&self, path: &Path) -> Result<Vec<u8>, ProfileFsError> {
            self.inner.read_file(path)
        }
        fn remove_file(&self, path: &Path) -> Result<(), ProfileFsError> {
            self.inner.remove_file(path)
        }
        fn remove_dir_all(&self, path: &Path) -> Result<(), ProfileFsError> {
            self.inner.remove_dir_all(path)
        }
    }

    /// Fake delegating to `inner` but failing `list_dir` on demand (models an
    /// enumeration failure C# `SweepStaleKeyedFolders` swallows).
    struct FailingListDirFs {
        inner: FakeProfileFs,
        fail_list_dir: bool,
    }

    impl ProfileFs for FailingListDirFs {
        fn is_dir(&self, path: &Path) -> bool {
            self.inner.is_dir(path)
        }
        fn list_dir(&self, path: &Path) -> Result<Vec<PathBuf>, ProfileFsError> {
            if self.fail_list_dir {
                return Err(ProfileFsError::Io);
            }
            self.inner.list_dir(path)
        }
        fn create_dir_all(&self, path: &Path) -> Result<(), ProfileFsError> {
            self.inner.create_dir_all(path)
        }
        fn read_file(&self, path: &Path) -> Result<Vec<u8>, ProfileFsError> {
            self.inner.read_file(path)
        }
        fn remove_file(&self, path: &Path) -> Result<(), ProfileFsError> {
            self.inner.remove_file(path)
        }
        fn remove_dir_all(&self, path: &Path) -> Result<(), ProfileFsError> {
            self.inner.remove_dir_all(path)
        }
    }

    #[test]
    fn fake_never_escapes_base_root() {
        let fs = FakeProfileFs::new(web_root()).unwrap();
        fs.seed_dir(web_root().join("shared-815e5671")).unwrap();
        fs.seed_file(web_root().join("env-a").join("Cookies"), b"x").unwrap();

        for hostile in [
            Path::new(r"..\escape"),
            Path::new(r"C:\Windows\evil"),
            Path::new(r"C:\Wormhole\webview2-webX"),
            Path::new(""),
        ] {
            assert_eq!(
                fs.read_file(hostile).unwrap_err(),
                ProfileFsError::PathNotConfined,
                "read {hostile:?}"
            );
            assert_eq!(
                fs.remove_file(hostile).unwrap_err(),
                ProfileFsError::PathNotConfined,
                "remove_file {hostile:?}"
            );
            assert_eq!(
                fs.remove_dir_all(hostile).unwrap_err(),
                ProfileFsError::PathNotConfined,
                "remove_dir_all {hostile:?}"
            );
            assert!(!fs.contains(hostile));
        }
        // Base contents untouched.
        assert!(fs.contains(web_root().join("shared-815e5671")));
        assert!(fs.contains_file(web_root().join("env-a").join("Cookies")));
        // Absolute sibling under base is allowed (symbolic prefixes).
        assert!(fs.contains(web_root().join("env-a")));
    }

    #[test]
    fn shared_and_isolated_fingerprint_dirs_are_wiped() {
        let fs = FakeProfileFs::new(web_root()).unwrap();
        fs.seed_file(web_root().join("shared-815e5671").join("Cookies"), b"c")
            .unwrap();
        fs.seed_file(web_root().join("shared-815e5671").join("Local State"), b"l")
            .unwrap();
        fs.seed_file(web_root().join("env-deadbeef").join("Cookies"), b"c")
            .unwrap();
        let g = glue(fs.clone());

        let report = g.wipe_web_browser_user_data().unwrap();

        assert_eq!(report.removed, 2);
        assert!(!report.was_empty);
        assert_eq!(report.failed, 0);
        assert!(!fs.contains_dir(web_root().join("shared-815e5671")));
        assert!(!fs.contains_dir(web_root().join("env-deadbeef")));
    }

    #[test]
    fn wipe_leaves_bitwarden_marker_files() {
        // Fake base = %LOCALAPPDATA%\Wormhole covers both disjoint sibling roots.
        let base = Path::new(r"C:\Wormhole");
        let fs = FakeProfileFs::new(base).unwrap();
        fs.seed_file(
            base.join("webview2-web").join("shared-815e5671").join("Cookies"),
            b"web",
        )
        .unwrap();
        // Bitwarden extension cookies / IDB live under the *separate* persistent root.
        let bw = base.join("bitwarden-browser-webview2").join("profile-context");
        fs.seed_file(bw.join("Cookies"), b"bw-cookies").unwrap();
        fs.seed_file(
            bw.join("Local Storage").join("leveldb").join("000003.log"),
            b"idb",
        )
        .unwrap();
        let g = glue(fs.clone());

        g.wipe_web_browser_user_data().unwrap();

        assert!(!fs.contains_dir(web_root().join("shared-815e5671")));
        assert!(fs.contains_file(bw.join("Cookies")));
        assert_eq!(
            fs.read_seeded(bw.join("Cookies")).unwrap(),
            b"bw-cookies"
        );
        assert!(fs.contains_file(
            bw.join("Local Storage").join("leveldb").join("000003.log")
        ));
    }

    #[test]
    fn wipe_removes_every_top_level_entry_under_root_only() {
        let fs = FakeProfileFs::new(web_root()).unwrap();
        fs.seed_file(web_root().join("shared-815e5671").join("x"), b"1").unwrap();
        fs.seed_file(web_root().join("shared-deadbeef").join("x"), b"2").unwrap();
        fs.seed_file(web_root().join("env-1").join("x"), b"3").unwrap();
        // A stray non-profile folder under the root is also reclaimed (C# deletes the root).
        fs.seed_file(web_root().join("EBWebView").join("x"), b"4").unwrap();
        let g = glue(fs.clone());

        let report = g.wipe_web_browser_user_data().unwrap();

        assert_eq!(report.removed, 4);
        // The container itself stays (deviation, avoids recreate race); all entries gone.
        assert!(fs.contains_dir(web_root()));
        let children = fs.list_dir(&web_root()).unwrap();
        assert!(children.is_empty());
    }

    #[test]
    fn hostile_path_escape_is_rejected_before_any_io() {
        let inner = FakeProfileFs::new(web_root()).unwrap();
        inner.seed_file(web_root().join("shared-815e5671").join("Cookies"), b"c")
            .unwrap();
        let hostile = web_root().join(r"..\outside");
        let fs = HostileListDirFs {
            inner: inner.clone(),
            hostile_extra: vec![hostile.clone()],
        };
        let g = ProfileWipeGlue::new(fs, web_root(), bw_root()).unwrap();

        assert_eq!(
            g.wipe_web_browser_user_data().unwrap_err(),
            HttpError::UnsafeProfilePath
        );
        // Nothing removed — hostile entry rejected before any IO.
        assert!(inner.contains_dir(web_root().join("shared-815e5671")));
        assert!(inner.contains_file(web_root().join("shared-815e5671").join("Cookies")));
        assert!(!inner.contains(&hostile));
    }

    #[test]
    fn sweep_hostile_path_escape_is_rejected_before_any_io() {
        let inner = FakeProfileFs::new(web_root()).unwrap();
        inner.seed_file(web_root().join("shared-deadbeef").join("x"), b"s")
            .unwrap();
        let hostile = web_root().join(r"..\outside");
        let fs = HostileListDirFs {
            inner: inner.clone(),
            hostile_extra: vec![hostile.clone()],
        };
        let g = ProfileWipeGlue::new(fs, web_root(), bw_root()).unwrap();

        assert_eq!(
            g.sweep_stale_keyed_folders().unwrap_err(),
            HttpError::UnsafeProfilePath
        );
        // Nothing removed — hostile entry rejected before any IO.
        assert!(inner.contains_dir(web_root().join("shared-deadbeef")));
        assert!(!inner.contains(&hostile));
    }

    #[test]
    fn sweep_enumeration_failure_is_tolerated_noop() {
        let inner = FakeProfileFs::new(web_root()).unwrap();
        inner.seed_file(web_root().join("shared-deadbeef").join("x"), b"s")
            .unwrap();
        let fs = FailingListDirFs {
            inner: inner.clone(),
            fail_list_dir: true,
        };
        let g = ProfileWipeGlue::new(fs, web_root(), bw_root()).unwrap();

        // C# swallows enumeration failure; nothing swept, nothing removed.
        assert_eq!(g.sweep_stale_keyed_folders().unwrap(), 0);
        assert!(inner.contains_dir(web_root().join("shared-deadbeef")));

        // Same Fake without the failure sweeps normally.
        let g = glue(inner.clone());
        assert_eq!(g.sweep_stale_keyed_folders().unwrap(), 1);
        assert!(!inner.contains_dir(web_root().join("shared-deadbeef")));
    }

    #[test]
    fn empty_root_is_idempotent_noop() {
        let fs = FakeProfileFs::new(web_root()).unwrap();
        fs.seed_dir(web_root()).unwrap();
        let g = glue(fs);
        let report = g.wipe_web_browser_user_data().unwrap();
        assert_eq!(report.removed, 0);
        assert!(report.was_empty);
        assert_eq!(report.failed, 0);

        // Missing root entirely → same no-op.
        let fs = FakeProfileFs::new(web_root()).unwrap();
        let report = glue(fs).wipe_web_browser_user_data().unwrap();
        assert_eq!(report.removed, 0);
        assert!(report.was_empty);
        assert_eq!(report.failed, 0);
    }

    #[test]
    fn locked_file_tolerated_remaining_folders_still_wiped() {
        let fs = FakeProfileFs::new(web_root()).unwrap();
        fs.seed_file(web_root().join("env-locked").join("Cookies"), b"locked")
            .unwrap();
        fs.lock_file(web_root().join("env-locked").join("Cookies"))
            .unwrap();
        fs.seed_file(web_root().join("shared-815e5671").join("Cookies"), b"ok")
            .unwrap();
        let g = glue(fs.clone());

        let report = g.wipe_web_browser_user_data().unwrap();

        assert_eq!(report.removed, 1);
        assert_eq!(report.failed, 1);
        assert!(!report.was_empty);
        // The clean folder was wiped; the tree under the locked file remains.
        assert!(!fs.contains_dir(web_root().join("shared-815e5671")));
        assert!(fs.contains_file(web_root().join("env-locked").join("Cookies")));
    }

    #[test]
    fn locked_dir_itself_tolerated_remaining_folders_wiped() {
        // Locking the top-level directory node (not just a file under it) must
        // block its removal while the remaining entries are still wiped.
        let fs = FakeProfileFs::new(web_root()).unwrap();
        fs.seed_file(web_root().join("env-locked").join("Cookies"), b"locked")
            .unwrap();
        fs.lock_file(web_root().join("env-locked")).unwrap();
        fs.seed_file(web_root().join("shared-815e5671").join("Cookies"), b"ok")
            .unwrap();
        let g = glue(fs.clone());

        let report = g.wipe_web_browser_user_data().unwrap();

        assert_eq!(report.removed, 1);
        assert_eq!(report.failed, 1);
        assert!(!report.was_empty);
        assert!(fs.contains_dir(web_root().join("env-locked")));
        assert!(!fs.contains_dir(web_root().join("shared-815e5671")));
    }

    #[test]
    fn sweep_removes_stale_shared_keeps_current_env_and_foreign() {
        let fs = FakeProfileFs::new(web_root()).unwrap();
        let current = keyed_shared_folder_name();
        fs.seed_file(web_root().join(&current).join("x"), b"cur").unwrap();
        fs.seed_file(web_root().join("shared-deadbeef").join("x"), b"stale")
            .unwrap();
        fs.seed_file(web_root().join("env-1234").join("x"), b"iso").unwrap();
        fs.seed_file(web_root().join("EBWebView").join("x"), b"foreign").unwrap();
        let g = glue(fs.clone());

        let removed = g.sweep_stale_keyed_folders().unwrap();

        assert_eq!(removed, 1);
        assert!(fs.contains_dir(web_root().join(&current)));
        assert!(!fs.contains_dir(web_root().join("shared-deadbeef")));
        assert!(fs.contains_dir(web_root().join("env-1234")));
        assert!(fs.contains_dir(web_root().join("EBWebView")));
    }

    #[test]
    fn sweep_missing_root_is_noop() {
        let fs = FakeProfileFs::new(web_root()).unwrap();
        assert_eq!(glue(fs).sweep_stale_keyed_folders().unwrap(), 0);
    }

    #[test]
    fn glue_rejects_empty_colliding_and_nested_roots() {
        let fs = FakeProfileFs::new(web_root()).unwrap();
        assert_eq!(
            ProfileWipeGlue::new(fs.clone(), PathBuf::new(), bw_root())
                .unwrap_err(),
            HttpError::EmptyPath
        );
        assert_eq!(
            ProfileWipeGlue::new(fs.clone(), web_root(), web_root()).unwrap_err(),
            HttpError::WebProfileRootCollision
        );
        assert_eq!(
            ProfileWipeGlue::new(fs.clone(), web_root(), web_root().join("bitwarden"))
                .unwrap_err(),
            HttpError::WebProfileRootCollision
        );
        assert_eq!(
            ProfileWipeGlue::new(fs.clone(), web_root(), r"C:\Wormhole").unwrap_err(),
            HttpError::WebProfileRootCollision
        );
        assert_eq!(
            ProfileWipeGlue::new(fs.clone(), PathBuf::from(r"C:\a\..\web"), bw_root())
                .unwrap_err(),
            HttpError::UnsafeProfilePath
        );
        assert!(
            ProfileWipeGlue::new(fs.clone(), web_root(), r"C:\Windows\evil").is_ok()
        );
    }

    #[test]
    fn curdir_normalized_nested_root_is_rejected() {
        // A `.` segment in one root must not bypass the nested-root collision
        // check: confinement folds CurDir, so the overlap guard must too.
        let fs = FakeProfileFs::new(web_root()).unwrap();
        let dot_root = PathBuf::from(r"C:\Wormhole\webview2-web\.");
        let nested = web_root().join("bitwarden");
        assert_eq!(
            ProfileWipeGlue::new(fs.clone(), dot_root.clone(), nested.clone()).unwrap_err(),
            HttpError::WebProfileRootCollision
        );
        assert_eq!(
            ProfileWipeGlue::new(fs.clone(), nested, dot_root.clone()).unwrap_err(),
            HttpError::WebProfileRootCollision
        );
        // A dot-root on its own is fine (it is the same directory as the clean root).
        assert!(ProfileWipeGlue::new(fs, dot_root, bw_root()).is_ok());
    }

    #[test]
    fn ensure_web_browser_user_data_dir_creates_shared_or_isolated() {
        let fs = FakeProfileFs::new(web_root()).unwrap();
        let g = glue(fs.clone());

        let shared = g
            .ensure_web_browser_user_data_dir(None, false, "unused")
            .unwrap();
        assert!(shared.ends_with(keyed_shared_folder_name()));
        assert!(fs.contains_dir(&shared));

        let socks = Socks5Proxy::loopback(1080).unwrap();
        let isolated = g
            .ensure_web_browser_user_data_dir(Some(socks), false, "abc123")
            .unwrap();
        assert_eq!(isolated, web_root().join("env-abc123"));
        assert!(fs.contains_dir(&isolated));

        let ignore = g
            .ensure_web_browser_user_data_dir(None, true, "cafebabe")
            .unwrap();
        assert_eq!(ignore, web_root().join("env-cafebabe"));
        assert!(fs.contains_dir(&ignore));

        // Empty isolated id while isolation is required fails closed (no dir created).
        assert_eq!(
            g.ensure_web_browser_user_data_dir(Some(socks), false, "")
                .unwrap_err(),
            HttpError::EmptyIsolatedId
        );
        assert!(!fs.contains_dir(web_root().join("env-")));
    }

    #[test]
    fn dir_resolvers_are_confined_and_fail_closed() {
        let fs = FakeProfileFs::new(web_root()).unwrap();
        let g = glue(fs);
        assert_eq!(
            g.web_browser_isolated_dir(r"..\evil").unwrap_err(),
            HttpError::EmptyIsolatedId
        );
        assert_eq!(
            g.web_browser_isolated_dir("ok-id").unwrap(),
            web_root().join("env-ok-id")
        );
        assert!(g
            .web_browser_shared_dir()
            .unwrap()
            .ends_with(keyed_shared_folder_name()));
    }

    #[test]
    fn real_profile_fs_glue_roundtrip_on_temp_dir() {
        let base = std::env::temp_dir().join(format!(
            "wormhole-http-profile-fs-{}",
            uuid::Uuid::new_v4().simple()
        ));
        let web = base.join("webview2-web");
        let bw = base.join("bitwarden-browser-webview2");
        let cleanup = || {
            let _ = std::fs::remove_dir_all(&base);
        };
        cleanup();
        std::fs::create_dir_all(web.join("shared-815e5671")).unwrap();
        std::fs::write(web.join("shared-815e5671").join("Cookies"), b"web").unwrap();
        std::fs::create_dir_all(bw.join("Local Storage").join("leveldb")).unwrap();
        std::fs::write(bw.join("Cookies"), b"bw").unwrap();
        std::fs::write(
            bw.join("Local Storage").join("leveldb").join("000003.log"),
            b"idb",
        )
        .unwrap();

        let g = ProfileWipeGlue::new(RealProfileFs, web.clone(), bw.clone()).unwrap();
        let report = g.wipe_web_browser_user_data().unwrap();

        assert_eq!(report.removed, 1);
        assert_eq!(report.failed, 0);
        assert!(!g.web_root().join("shared-815e5671").exists());
        assert!(bw.join("Cookies").exists());
        assert!(bw.join("Local Storage").join("leveldb").join("000003.log").exists());

        // Idempotent second wipe.
        let report = g.wipe_web_browser_user_data().unwrap();
        assert_eq!(report.removed, 0);
        assert!(report.was_empty);

        // ensure dir creates the fingerprint folder on the real disk.
        let created = g
            .ensure_web_browser_user_data_dir(None, false, "")
            .unwrap();
        assert!(created.exists());
        assert!(created.is_dir());

        cleanup();
    }

    #[test]
    fn debug_shows_counts_and_paths_not_contents() {
        let fs = FakeProfileFs::new(web_root()).unwrap();
        fs.seed_file(web_root().join("shared-815e5671").join("Cookies"), b"top-secret")
            .unwrap();
        fs.lock_file(web_root().join("shared-815e5671").join("Cookies"))
            .unwrap();
        let dbg = format!("{fs:?}");
        assert!(dbg.contains("base_root_len"));
        assert!(dbg.contains("entry_count"));
        assert!(!dbg.contains("top-secret"));
        assert!(!dbg.contains("Cookies"));

        let report = ProfileWipeReport {
            removed: 3,
            was_empty: false,
            failed: 1,
        };
        let dbg = format!("{report:?}");
        assert!(dbg.contains("removed"));
        assert!(dbg.contains("failed"));
        assert!(!dbg.contains("secret"));

        // Glue Debug shows root lengths and the FS summary, never paths.
        let glue = ProfileWipeGlue::new(fs, web_root(), bw_root()).unwrap();
        let glue_dbg = format!("{glue:?}");
        assert!(glue_dbg.contains("web_root_len"));
        assert!(glue_dbg.contains("bitwarden_root_len"));
        assert!(glue_dbg.contains("entry_count"));
        assert!(!glue_dbg.contains(r"C:\Wormhole"));
        assert!(!glue_dbg.contains("Cookies"));
    }

    #[test]
    fn profile_fs_error_display_never_embeds_paths() {
        for err in [
            ProfileFsError::PathNotConfined,
            ProfileFsError::NotFound,
            ProfileFsError::Io,
        ] {
            let text = format!("{err} / {err:?}");
            assert!(!text.contains(r"C:\"));
            assert!(!text.contains(".."));
        }
        let converted: HttpError = ProfileFsError::Io.into();
        let text = format!("{converted}");
        assert!(!text.contains(r"C:\"));
    }

    #[test]
    fn target_based_ensure_uses_resolved_cert_policy() {
        let fs = FakeProfileFs::new(web_root()).unwrap();
        let g = glue(fs.clone());
        let https_ignore = build_direct_target(HttpScheme::Https, "r", 443, true).unwrap();
        let socks = build_socks_target(
            HttpScheme::Http,
            "r",
            80,
            false,
            Socks5Proxy::loopback(1080).unwrap(),
            None,
        )
        .unwrap();
        let path = g
            .ensure_web_browser_user_data_dir(socks.socks5_proxy, socks.ignore_cert_errors(), "iso9")
            .unwrap();
        assert_eq!(path, web_root().join("env-iso9"));
        assert!(https_ignore.ignore_cert_errors());
        let path2 = g
            .ensure_web_browser_user_data_dir(
                https_ignore.socks5_proxy,
                https_ignore.ignore_cert_errors(),
                "iso8",
            )
            .unwrap();
        assert_eq!(path2, web_root().join("env-iso8"));
    }
}
