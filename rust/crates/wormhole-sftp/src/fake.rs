//! In-memory SFTP backend for unit tests (no network / no russh).

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;
use tokio::time::sleep;

use crate::entry::SftpEntry;
use crate::ops::SftpOps;
use crate::path::is_safe_remote_name;
use crate::SftpError;

#[derive(Debug, Clone)]
enum Node {
    Dir,
    File(Vec<u8>),
}

/// Fake remote filesystem with optional artificial latency (to prove serialization).
pub struct FakeSftpBackend {
    cwd: String,
    fingerprint: Option<String>,
    connected: AtomicBool,
    tree: Mutex<BTreeMap<String, Node>>,
    /// Milliseconds to sleep at the start of every op (tests use this to overlap callers).
    pub op_delay: Mutex<Duration>,
    /// How many ops are currently inside the backend (must stay ≤1 when wrapped).
    pub in_flight: AtomicUsize,
    /// Peak observed `in_flight` — serialization tests assert this stays at 1.
    pub peak_in_flight: AtomicUsize,
    pub call_count: AtomicUsize,
}

impl FakeSftpBackend {
    pub fn new() -> Self {
        let mut tree = BTreeMap::new();
        tree.insert("/".into(), Node::Dir);
        tree.insert("/home".into(), Node::Dir);
        tree.insert("/home/user".into(), Node::Dir);
        Self {
            cwd: "/home/user".into(),
            fingerprint: Some("SHA256:fake".into()),
            connected: AtomicBool::new(true),
            tree: Mutex::new(tree),
            op_delay: Mutex::new(Duration::ZERO),
            in_flight: AtomicUsize::new(0),
            peak_in_flight: AtomicUsize::new(0),
            call_count: AtomicUsize::new(0),
        }
    }

    pub fn with_delay(delay: Duration) -> Self {
        let s = Self::new();
        *s.op_delay.lock().unwrap_or_else(|p| p.into_inner()) = delay;
        s
    }

    pub fn seed_file(&self, path: &str, data: &[u8]) {
        let mut tree = self.tree.lock().unwrap_or_else(|p| p.into_inner());
        ensure_parents(&mut tree, path);
        tree.insert(path.to_string(), Node::File(data.to_vec()));
    }

    async fn enter(&self) -> InFlightGuard<'_> {
        self.call_count.fetch_add(1, Ordering::SeqCst);
        let now = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
        self.peak_in_flight.fetch_max(now, Ordering::SeqCst);
        // Guard must exist before any `.await` so cancel mid-delay still decrements.
        let guard = InFlightGuard { backend: self };
        let delay = *self.op_delay.lock().unwrap_or_else(|p| p.into_inner());
        if !delay.is_zero() {
            sleep(delay).await;
        }
        guard
    }

    fn normalize(path: &str) -> String {
        if path.is_empty() {
            "/".into()
        } else if path.starts_with('/') {
            path.trim_end_matches('/').to_string()
        } else {
            format!("/{}", path.trim_end_matches('/'))
        }
    }
}

impl Default for FakeSftpBackend {
    fn default() -> Self {
        Self::new()
    }
}

fn ensure_parents(tree: &mut BTreeMap<String, Node>, path: &str) {
    let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    if parts.is_empty() {
        return;
    }
    let mut cur = String::new();
    for part in &parts[..parts.len().saturating_sub(1)] {
        cur = if cur.is_empty() {
            format!("/{part}")
        } else {
            format!("{cur}/{part}")
        };
        tree.entry(cur.clone()).or_insert(Node::Dir);
    }
}

fn parent_and_name(path: &str) -> Option<(String, String)> {
    let norm = FakeSftpBackend::normalize(path);
    if norm == "/" {
        return None;
    }
    match norm.rsplit_once('/') {
        Some(("", name)) => Some(("/".into(), name.to_string())),
        Some((parent, name)) => Some((parent.to_string(), name.to_string())),
        None => None,
    }
}

/// RAII: always decrements `in_flight`, even if the op future is cancelled mid-delay.
struct InFlightGuard<'a> {
    backend: &'a FakeSftpBackend,
}

impl Drop for InFlightGuard<'_> {
    fn drop(&mut self) {
        self.backend.in_flight.fetch_sub(1, Ordering::SeqCst);
    }
}

fn reject_unsafe_leaf(path: &str) -> Result<(), SftpError> {
    if let Some((_, name)) = parent_and_name(path)
        && !is_safe_remote_name(&name)
    {
        return Err(SftpError::UnsafeName(name));
    }
    Ok(())
}

#[async_trait]
impl SftpOps for FakeSftpBackend {
    fn working_directory(&self) -> &str {
        &self.cwd
    }

    fn host_fingerprint(&self) -> Option<&str> {
        self.fingerprint.as_deref()
    }

    fn is_connected(&self) -> bool {
        self.connected.load(Ordering::SeqCst)
    }

    async fn list_directory(&self, path: &str) -> Result<Vec<SftpEntry>, SftpError> {
        let _guard = self.enter().await;
        let norm = Self::normalize(path);
        let tree = self.tree.lock().unwrap_or_else(|p| p.into_inner());
        match tree.get(&norm) {
            Some(Node::Dir) => {}
            Some(Node::File(_)) => {
                return Err(SftpError::Operation(format!("{norm} is not a directory")));
            }
            None => return Err(SftpError::NotFound(norm)),
        }
        let prefix = if norm == "/" {
            "/".to_string()
        } else {
            format!("{norm}/")
        };
        let mut entries = Vec::new();
        for (p, node) in tree.iter() {
            if !p.starts_with(&prefix) || p == &norm {
                continue;
            }
            let rest = &p[prefix.len()..];
            if rest.contains('/') {
                continue; // only direct children
            }
            if !is_safe_remote_name(rest) {
                continue;
            }
            entries.push(match node {
                Node::Dir => SftpEntry::directory(rest, p.clone()),
                Node::File(data) => SftpEntry::file(rest, p.clone(), data.len() as u64),
            });
        }
        Ok(entries)
    }

    async fn get_attributes(&self, path: &str) -> Result<Option<SftpEntry>, SftpError> {
        let _guard = self.enter().await;
        let norm = Self::normalize(path);
        let tree = self.tree.lock().unwrap_or_else(|p| p.into_inner());
        let entry = match tree.get(&norm) {
            Some(Node::Dir) => {
                let name = parent_and_name(&norm).map(|(_, n)| n).unwrap_or_default();
                Some(SftpEntry::directory(name, norm))
            }
            Some(Node::File(data)) => {
                let name = parent_and_name(&norm).map(|(_, n)| n).unwrap_or_default();
                Some(SftpEntry::file(name, norm, data.len() as u64))
            }
            None => None,
        };
        Ok(entry)
    }

    async fn exists(&self, path: &str) -> Result<bool, SftpError> {
        let _guard = self.enter().await;
        let norm = Self::normalize(path);
        let exists = self
            .tree
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .contains_key(&norm);
        Ok(exists)
    }

    async fn upload(&self, remote_path: &str, data: &[u8]) -> Result<(), SftpError> {
        let _guard = self.enter().await;
        let norm = Self::normalize(remote_path);
        reject_unsafe_leaf(&norm)?;
        let mut tree = self.tree.lock().unwrap_or_else(|p| p.into_inner());
        ensure_parents(&mut tree, &norm);
        tree.insert(norm, Node::File(data.to_vec()));
        Ok(())
    }

    async fn download(&self, remote_path: &str) -> Result<Vec<u8>, SftpError> {
        let _guard = self.enter().await;
        let norm = Self::normalize(remote_path);
        let tree = self.tree.lock().unwrap_or_else(|p| p.into_inner());
        match tree.get(&norm) {
            Some(Node::File(data)) => Ok(data.clone()),
            Some(Node::Dir) => Err(SftpError::Operation(format!("{norm} is a directory"))),
            None => Err(SftpError::NotFound(norm)),
        }
    }

    async fn create_directory(&self, remote_path: &str) -> Result<(), SftpError> {
        let _guard = self.enter().await;
        let norm = Self::normalize(remote_path);
        reject_unsafe_leaf(&norm)?;
        let mut tree = self.tree.lock().unwrap_or_else(|p| p.into_inner());
        ensure_parents(&mut tree, &norm);
        tree.insert(norm, Node::Dir);
        Ok(())
    }

    async fn create_empty_file(&self, remote_path: &str) -> Result<(), SftpError> {
        let _guard = self.enter().await;
        let norm = Self::normalize(remote_path);
        reject_unsafe_leaf(&norm)?;
        let mut tree = self.tree.lock().unwrap_or_else(|p| p.into_inner());
        ensure_parents(&mut tree, &norm);
        tree.insert(norm, Node::File(Vec::new()));
        Ok(())
    }

    async fn delete_file(&self, remote_path: &str) -> Result<(), SftpError> {
        let _guard = self.enter().await;
        let norm = Self::normalize(remote_path);
        let mut tree = self.tree.lock().unwrap_or_else(|p| p.into_inner());
        match tree.get(&norm) {
            Some(Node::File(_)) => {
                tree.remove(&norm);
                Ok(())
            }
            Some(Node::Dir) => Err(SftpError::Operation(format!("{norm} is a directory"))),
            None => Err(SftpError::NotFound(norm)),
        }
    }

    async fn delete_directory(&self, remote_path: &str, recursive: bool) -> Result<(), SftpError> {
        let _guard = self.enter().await;
        let norm = Self::normalize(remote_path);
        if norm == "/" {
            return Err(SftpError::Operation("cannot delete root".into()));
        }
        let mut tree = self.tree.lock().unwrap_or_else(|p| p.into_inner());
        match tree.get(&norm) {
            Some(Node::Dir) => {}
            Some(Node::File(_)) => {
                return Err(SftpError::Operation(format!("{norm} is not a directory")));
            }
            None => return Err(SftpError::NotFound(norm)),
        }
        let prefix = format!("{norm}/");
        let children: Vec<String> = tree
            .keys()
            .filter(|p| p.starts_with(&prefix) || *p == &norm)
            .cloned()
            .collect();
        if children.len() > 1 && !recursive {
            return Err(SftpError::Operation(format!("{norm} is not empty")));
        }
        for p in children {
            tree.remove(&p);
        }
        Ok(())
    }

    async fn rename(&self, old_path: &str, new_path: &str) -> Result<(), SftpError> {
        let _guard = self.enter().await;
        let old = Self::normalize(old_path);
        let new = Self::normalize(new_path);
        reject_unsafe_leaf(&new)?;
        let mut tree = self.tree.lock().unwrap_or_else(|p| p.into_inner());
        let Some(node) = tree.remove(&old) else {
            return Err(SftpError::NotFound(old));
        };
        ensure_parents(&mut tree, &new);
        tree.insert(new, node);
        Ok(())
    }
}
