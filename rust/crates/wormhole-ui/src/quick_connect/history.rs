//! Quick Connect recent-history VM glue (pure Rust; no GPUI).
//!
//! Records **successful** QC targets as `protocol + host [+ port]` in a capped
//! MRU list. Persistence is abstracted behind [`QuickConnectHistoryStore`]; unit
//! tests use [`FakeQuickConnectHistoryStore`]. Never stores passwords or secrets.
//!
//! Fail-closed: blank / whitespace-only hosts are rejected and do not mutate the
//! list. Dedup key is protocol + case-insensitive trimmed host + optional port
//! (protocol default ports collapse to `None`; Serial / HTTP(S) address shape
//! matches [`ConnectionNode`] after `write_to`).

use std::collections::HashSet;
use std::fmt;
use std::sync::Mutex;

use thiserror::Error;
use wormhole_domain::{ConnectionNode, ProtocolType};

use crate::connection_editor::{format_http_address, parse_http_address};

use super::{default_port, QuickConnectResult, QuickConnectState};

/// Default MRU capacity (oldest entries drop when exceeded after dedupe).
pub const DEFAULT_HISTORY_CAPACITY: usize = 10;

/// Errors from recent-history record / store IO.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum QuickConnectHistoryError {
    /// Host was empty or whitespace-only — list unchanged.
    #[error("quick connect history host must be non-empty")]
    EmptyHost,
    #[error("quick connect history store error: {0}")]
    Store(String),
}

/// One recent Quick Connect target (no credentials).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuickConnectHistoryEntry {
    pub protocol: ProtocolType,
    /// Trimmed display host / COM line (casing from last successful record).
    ///
    /// For HTTP(S) this is the **bare** host (port lives in [`Self::port`]), matching
    /// `ConnectionNode` after editor `write_to`.
    pub host: String,
    /// Explicit port when set (`1..=65535`). `None` for protocol default / Serial.
    pub port: Option<u16>,
}

impl QuickConnectHistoryEntry {
    /// Build an entry from protocol + host [+ port]. Trims host; rejects blank.
    pub fn try_new(
        protocol: ProtocolType,
        host: impl Into<String>,
        port: Option<u16>,
    ) -> Result<Self, QuickConnectHistoryError> {
        let (host, port) = normalize_parts(protocol, &host.into(), port)?;
        Ok(Self {
            protocol,
            host,
            port,
        })
    }

    /// Dedup key: protocol + lowercase host + normalized port.
    pub fn key(&self) -> QuickConnectHistoryKey {
        QuickConnectHistoryKey {
            protocol: self.protocol,
            host_key: self.host.to_ascii_lowercase(),
            port: self.port,
        }
    }

    /// Short label for MRU chrome (`ssh example.com:2222`, `serial COM1`, …).
    pub fn display_label(&self) -> String {
        let proto = self.protocol.to_string().to_ascii_lowercase();
        match self.protocol {
            ProtocolType::Serial => format!("{proto} {}", self.host),
            ProtocolType::Http | ProtocolType::Https => {
                format!("{proto} {}", format_http_address(&self.host, self.port))
            }
            _ => match self.port {
                Some(port) => format!("{proto} {}:{}", self.host, port),
                None => format!("{proto} {}", self.host),
            },
        }
    }
}

/// Stable identity for dedupe / remove.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct QuickConnectHistoryKey {
    pub protocol: ProtocolType,
    pub host_key: String,
    pub port: Option<u16>,
}

impl QuickConnectHistoryKey {
    pub fn from_parts(
        protocol: ProtocolType,
        host: &str,
        port: Option<u16>,
    ) -> Result<Self, QuickConnectHistoryError> {
        let (host, port) = normalize_parts(protocol, host, port)?;
        Ok(Self {
            protocol,
            host_key: host.to_ascii_lowercase(),
            port,
        })
    }
}

/// Persistence backend for the MRU list (Fake in tests; file/SQLite later).
pub trait QuickConnectHistoryStore: Send + Sync {
    fn load(&self) -> Result<Vec<QuickConnectHistoryEntry>, QuickConnectHistoryError>;
    fn save(&self, entries: &[QuickConnectHistoryEntry]) -> Result<(), QuickConnectHistoryError>;
}

/// In-memory Fake store for unit tests and hosts without persistence yet.
#[derive(Debug, Default)]
pub struct FakeQuickConnectHistoryStore {
    inner: Mutex<Vec<QuickConnectHistoryEntry>>,
}

impl FakeQuickConnectHistoryStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_entries(entries: Vec<QuickConnectHistoryEntry>) -> Self {
        Self {
            inner: Mutex::new(entries),
        }
    }

    pub fn snapshot(&self) -> Vec<QuickConnectHistoryEntry> {
        self.inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }
}

impl QuickConnectHistoryStore for FakeQuickConnectHistoryStore {
    fn load(&self) -> Result<Vec<QuickConnectHistoryEntry>, QuickConnectHistoryError> {
        Ok(self
            .inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone())
    }

    fn save(&self, entries: &[QuickConnectHistoryEntry]) -> Result<(), QuickConnectHistoryError> {
        *self.inner.lock().unwrap_or_else(|p| p.into_inner()) = entries.to_vec();
        Ok(())
    }
}

/// Pure Quick Connect recent-history view-model (no GPUI).
///
/// Call [`record_success`] after a successful connect; entries are newest-first.
pub struct QuickConnectHistoryVm {
    store: Box<dyn QuickConnectHistoryStore>,
    entries: Vec<QuickConnectHistoryEntry>,
    capacity: usize,
}

impl fmt::Debug for QuickConnectHistoryVm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QuickConnectHistoryVm")
            .field("entries", &self.entries)
            .field("capacity", &self.capacity)
            .field("store", &"<QuickConnectHistoryStore>")
            .finish()
    }
}

impl QuickConnectHistoryVm {
    /// Load from an injected store with [`DEFAULT_HISTORY_CAPACITY`].
    pub fn new(store: Box<dyn QuickConnectHistoryStore>) -> Result<Self, QuickConnectHistoryError> {
        Self::with_capacity(store, DEFAULT_HISTORY_CAPACITY)
    }

    /// Load from store with an explicit MRU cap (`0` keeps the list empty).
    ///
    /// Truncates oversized loads and persists the clamp so a smaller capacity
    /// does not leave orphans in the backing store. Also drops blank-host /
    /// duplicate-key orphans from a dirty store.
    pub fn with_capacity(
        store: Box<dyn QuickConnectHistoryStore>,
        capacity: usize,
    ) -> Result<Self, QuickConnectHistoryError> {
        let loaded = store.load()?;
        let entries = sanitize_loaded(&loaded, capacity);
        if entries != loaded {
            store.save(&entries)?;
        }
        Ok(Self {
            store,
            entries,
            capacity,
        })
    }

    /// Empty Fake-backed VM (preferred test constructor).
    pub fn fake() -> Self {
        Self {
            store: Box::new(FakeQuickConnectHistoryStore::new()),
            entries: Vec::new(),
            capacity: DEFAULT_HISTORY_CAPACITY,
        }
    }

    /// Empty Fake-backed VM with custom capacity.
    pub fn fake_with_capacity(capacity: usize) -> Self {
        Self {
            store: Box::new(FakeQuickConnectHistoryStore::new()),
            entries: Vec::new(),
            capacity,
        }
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Newest-first MRU snapshot.
    pub fn entries(&self) -> &[QuickConnectHistoryEntry] {
        &self.entries
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Record a successful QC target. Dedupes by key (moves to front); caps MRU.
    ///
    /// Fail-closed on blank host — returns [`QuickConnectHistoryError::EmptyHost`]
    /// and leaves the list unchanged.
    pub fn record_success(
        &mut self,
        protocol: ProtocolType,
        host: impl Into<String>,
        port: Option<u16>,
    ) -> Result<(), QuickConnectHistoryError> {
        let entry = QuickConnectHistoryEntry::try_new(protocol, host, port)?;
        self.insert_front(entry)?;
        Ok(())
    }

    /// Record from an accepted [`QuickConnectResult`] node (password ignored).
    pub fn record_success_from_result(
        &mut self,
        result: &QuickConnectResult,
    ) -> Result<(), QuickConnectHistoryError> {
        self.record_success_from_node(&result.node)
    }

    /// Record from a connection node / ephemeral profile target fields.
    pub fn record_success_from_node(
        &mut self,
        node: &ConnectionNode,
    ) -> Result<(), QuickConnectHistoryError> {
        let protocol = node.protocol.unwrap_or(ProtocolType::Ssh);
        let host = node.host.clone().unwrap_or_default();
        let port = node_port_u16(protocol, node.port);
        self.record_success(protocol, host, port)
    }

    /// Remove every entry matching `key` (no-op if missing).
    pub fn remove(&mut self, key: &QuickConnectHistoryKey) -> Result<bool, QuickConnectHistoryError> {
        if !self.entries.iter().any(|e| &e.key() == key) {
            return Ok(false);
        }
        let next: Vec<_> = self
            .entries
            .iter()
            .filter(|e| &e.key() != key)
            .cloned()
            .collect();
        self.commit(next)?;
        Ok(true)
    }

    /// Remove by index (newest = 0). Returns `false` when out of range.
    pub fn remove_at(&mut self, index: usize) -> Result<bool, QuickConnectHistoryError> {
        if index >= self.entries.len() {
            return Ok(false);
        }
        let mut next = self.entries.clone();
        next.remove(index);
        self.commit(next)?;
        Ok(true)
    }

    /// Clear all history entries.
    pub fn clear(&mut self) -> Result<(), QuickConnectHistoryError> {
        if self.entries.is_empty() {
            return Ok(());
        }
        self.commit(Vec::new())
    }

    /// Reload from the backing store (replaces in-memory list; reapplies capacity).
    ///
    /// Persists the clamp / sanitize when the store held more than `capacity`,
    /// blank hosts, or duplicate keys — matching [`Self::with_capacity`].
    pub fn reload(&mut self) -> Result<(), QuickConnectHistoryError> {
        let loaded = self.store.load()?;
        let entries = sanitize_loaded(&loaded, self.capacity);
        if entries != loaded {
            self.store.save(&entries)?;
        }
        self.entries = entries;
        Ok(())
    }

    /// Seed [`QuickConnectState`] protocol / host / port from a history entry.
    ///
    /// Does not touch credentials, tunnel, or serial baud settings.
    pub fn apply_to_quick_connect(entry: &QuickConnectHistoryEntry, qc: &mut QuickConnectState) {
        qc.set_protocol(entry.protocol);
        match entry.protocol {
            ProtocolType::Serial => {
                qc.set_host(entry.host.clone());
                qc.set_port(None);
            }
            ProtocolType::Http | ProtocolType::Https => {
                // Address field carries `host[:port]` (IPv6 bracketed when needed).
                qc.set_host(format_http_address(&entry.host, entry.port));
                qc.set_port(None);
            }
            ProtocolType::Ssh | ProtocolType::Rdp | ProtocolType::Vnc => {
                qc.set_host(entry.host.clone());
                qc.set_port(entry.port.map(i32::from));
            }
        }
    }

    fn insert_front(
        &mut self,
        entry: QuickConnectHistoryEntry,
    ) -> Result<(), QuickConnectHistoryError> {
        let key = entry.key();
        let mut next = self.entries.clone();
        next.retain(|e| e.key() != key);
        next.insert(0, entry);
        clamp_mru(&mut next, self.capacity);
        self.commit(next)
    }

    /// Persist first, then swap memory — fail closed leaves prior entries intact.
    fn commit(
        &mut self,
        entries: Vec<QuickConnectHistoryEntry>,
    ) -> Result<(), QuickConnectHistoryError> {
        self.store.save(&entries)?;
        self.entries = entries;
        Ok(())
    }
}

fn normalize_parts(
    protocol: ProtocolType,
    host: &str,
    port: Option<u16>,
) -> Result<(String, Option<u16>), QuickConnectHistoryError> {
    match protocol {
        ProtocolType::Http | ProtocolType::Https => {
            let (parsed_host, parsed_port) = parse_http_address(host);
            let trimmed = parsed_host.trim();
            if trimmed.is_empty() {
                return Err(QuickConnectHistoryError::EmptyHost);
            }
            // Prefer port embedded in the address string; else the explicit arg.
            let port = match parsed_port {
                Some(p) if (1..=65535).contains(&p) => Some(p as u16),
                _ => port,
            };
            Ok((trimmed.to_owned(), normalize_port(protocol, port)))
        }
        _ => {
            let trimmed = host.trim();
            if trimmed.is_empty() {
                return Err(QuickConnectHistoryError::EmptyHost);
            }
            Ok((trimmed.to_owned(), normalize_port(protocol, port)))
        }
    }
}

fn normalize_port(protocol: ProtocolType, port: Option<u16>) -> Option<u16> {
    if protocol == ProtocolType::Serial {
        return None;
    }
    let port = port.filter(|p| (1..=65535).contains(p))?;
    // Collapse protocol defaults so implicit None and explicit default dedupe.
    let default = default_port(protocol);
    if default > 0 && i32::from(port) == default {
        return None;
    }
    Some(port)
}

fn node_port_u16(protocol: ProtocolType, port: Option<i32>) -> Option<u16> {
    if protocol == ProtocolType::Serial {
        return None;
    }
    match port {
        Some(p) if (1..=65535).contains(&p) => Some(p as u16),
        _ => None,
    }
}

fn clamp_mru(entries: &mut Vec<QuickConnectHistoryEntry>, capacity: usize) {
    if entries.len() > capacity {
        entries.truncate(capacity);
    }
}

/// Drop blank hosts, re-normalize keys, dedupe (first/newest wins), then capacity.
fn sanitize_loaded(
    loaded: &[QuickConnectHistoryEntry],
    capacity: usize,
) -> Vec<QuickConnectHistoryEntry> {
    let mut out = Vec::with_capacity(loaded.len().min(capacity.max(1)));
    let mut seen = HashSet::new();
    for entry in loaded {
        let Ok(normalized) =
            QuickConnectHistoryEntry::try_new(entry.protocol, entry.host.as_str(), entry.port)
        else {
            continue;
        };
        if !seen.insert(normalized.key()) {
            continue;
        }
        out.push(normalized);
    }
    clamp_mru(&mut out, capacity);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use uuid::Uuid;
    use wormhole_domain::NodeKind;

    #[test]
    fn record_success_mru_order_and_cap() {
        let mut vm = QuickConnectHistoryVm::fake_with_capacity(3);
        vm.record_success(ProtocolType::Ssh, "a.example", Some(22))
            .unwrap();
        vm.record_success(ProtocolType::Ssh, "b.example", Some(22))
            .unwrap();
        vm.record_success(ProtocolType::Rdp, "c.example", Some(3389))
            .unwrap();
        vm.record_success(ProtocolType::Vnc, "d.example", None)
            .unwrap();

        assert_eq!(vm.len(), 3);
        assert_eq!(vm.entries()[0].host, "d.example");
        assert_eq!(vm.entries()[1].host, "c.example");
        assert_eq!(vm.entries()[2].host, "b.example");
        // Defaults collapsed to None.
        assert_eq!(vm.entries()[1].port, None);
        assert_eq!(vm.entries()[2].port, None);
    }

    #[test]
    fn dedupe_by_protocol_host_port_moves_to_front() {
        let mut vm = QuickConnectHistoryVm::fake();
        vm.record_success(ProtocolType::Ssh, "Host.Example", Some(22))
            .unwrap();
        vm.record_success(ProtocolType::Ssh, "other", Some(22))
            .unwrap();
        // Case-insensitive host match; same protocol + default port → replace + front.
        vm.record_success(ProtocolType::Ssh, "host.example", Some(22))
            .unwrap();

        assert_eq!(vm.len(), 2);
        assert_eq!(vm.entries()[0].host, "host.example");
        assert_eq!(vm.entries()[1].host, "other");
    }

    #[test]
    fn different_port_is_distinct_key() {
        let mut vm = QuickConnectHistoryVm::fake();
        vm.record_success(ProtocolType::Ssh, "h", Some(22)).unwrap();
        vm.record_success(ProtocolType::Ssh, "h", Some(2222))
            .unwrap();
        assert_eq!(vm.len(), 2);
    }

    #[test]
    fn default_port_none_and_explicit_dedupe() {
        let mut vm = QuickConnectHistoryVm::fake();
        vm.record_success(ProtocolType::Ssh, "lab", None).unwrap();
        vm.record_success(ProtocolType::Ssh, "lab", Some(22))
            .unwrap();
        assert_eq!(vm.len(), 1);
        assert_eq!(vm.entries()[0].port, None);
    }

    #[test]
    fn empty_host_fail_closed() {
        let mut vm = QuickConnectHistoryVm::fake();
        vm.record_success(ProtocolType::Ssh, "ok", Some(22))
            .unwrap();
        let err = vm
            .record_success(ProtocolType::Ssh, "   ", Some(22))
            .unwrap_err();
        assert_eq!(err, QuickConnectHistoryError::EmptyHost);
        assert_eq!(vm.len(), 1);
        assert_eq!(vm.entries()[0].host, "ok");
    }

    #[test]
    fn clear_and_remove() {
        let mut vm = QuickConnectHistoryVm::fake();
        vm.record_success(ProtocolType::Ssh, "a", Some(22)).unwrap();
        vm.record_success(ProtocolType::Rdp, "b", None).unwrap();
        let key = QuickConnectHistoryKey::from_parts(ProtocolType::Ssh, "a", Some(22)).unwrap();
        assert!(vm.remove(&key).unwrap());
        assert_eq!(vm.len(), 1);
        assert!(!vm.remove(&key).unwrap());
        vm.clear().unwrap();
        assert!(vm.is_empty());
    }

    #[test]
    fn remove_at_and_serial_ignores_port() {
        let mut vm = QuickConnectHistoryVm::fake();
        vm.record_success(ProtocolType::Serial, "COM1", Some(99))
            .unwrap();
        assert_eq!(vm.entries()[0].port, None);
        // Same COM with different port arg still dedupes.
        vm.record_success(ProtocolType::Serial, "com1", Some(1))
            .unwrap();
        assert_eq!(vm.len(), 1);
        assert!(vm.remove_at(0).unwrap());
        assert!(!vm.remove_at(0).unwrap());
    }

    #[test]
    fn record_from_result_and_apply_to_qc() {
        let mut qc = QuickConnectState::new();
        qc.set_protocol(ProtocolType::Ssh);
        qc.set_host("lab.local");
        qc.set_port(Some(2222));
        let result = qc.try_build().unwrap();

        let mut history = QuickConnectHistoryVm::fake();
        history.record_success_from_result(&result).unwrap();
        assert_eq!(history.entries()[0].host, "lab.local");
        assert_eq!(history.entries()[0].port, Some(2222));

        let mut qc2 = QuickConnectState::new();
        QuickConnectHistoryVm::apply_to_quick_connect(&history.entries()[0], &mut qc2);
        assert_eq!(qc2.protocol(), ProtocolType::Ssh);
        assert_eq!(qc2.host(), "lab.local");
        assert_eq!(qc2.port(), Some(2222));
    }

    #[test]
    fn http_from_result_preserves_port_on_apply() {
        let mut qc = QuickConnectState::new();
        qc.set_protocol(ProtocolType::Http);
        qc.set_host("fw.local:8443");
        let result = qc.try_build().unwrap();
        assert_eq!(result.node.host.as_deref(), Some("fw.local"));
        assert_eq!(result.node.port, Some(8443));

        let mut history = QuickConnectHistoryVm::fake();
        history.record_success_from_result(&result).unwrap();
        assert_eq!(history.entries()[0].host, "fw.local");
        assert_eq!(history.entries()[0].port, Some(8443));

        let mut qc2 = QuickConnectState::new();
        QuickConnectHistoryVm::apply_to_quick_connect(&history.entries()[0], &mut qc2);
        assert_eq!(qc2.protocol(), ProtocolType::Http);
        assert_eq!(qc2.host(), "fw.local:8443");
        assert_eq!(qc2.port(), None);
        assert!(qc2.inline_password().is_empty());
    }

    #[test]
    fn record_from_result_ignores_password() {
        let mut qc = QuickConnectState::new();
        qc.set_protocol(ProtocolType::Ssh);
        qc.set_host("lab.local");
        qc.set_port(Some(2222));
        let built = qc.try_build().unwrap();
        let result = QuickConnectResult::new(
            built.node,
            Some("s3cret-must-not-land-in-history".into()),
        );

        let mut history = QuickConnectHistoryVm::fake();
        history.record_success_from_result(&result).unwrap();
        let entry_dbg = format!("{:?}", history.entries()[0]);
        let hist_dbg = format!("{history:?}");
        assert!(!entry_dbg.contains("s3cret"));
        assert!(!hist_dbg.contains("s3cret"));
        assert_eq!(history.entries()[0].host, "lab.local");
    }

    #[test]
    fn https_ipv6_apply_brackets_port() {
        let entry =
            QuickConnectHistoryEntry::try_new(ProtocolType::Https, "fd00::1", Some(8443)).unwrap();
        assert_eq!(entry.display_label(), "https [fd00::1]:8443");
        let mut qc = QuickConnectState::new();
        QuickConnectHistoryVm::apply_to_quick_connect(&entry, &mut qc);
        assert_eq!(qc.host(), "[fd00::1]:8443");
    }

    #[test]
    fn fake_store_round_trip_via_vm_new() {
        let store = FakeQuickConnectHistoryStore::with_entries(vec![
            QuickConnectHistoryEntry::try_new(ProtocolType::Http, "10.0.0.1:8443", None).unwrap(),
        ]);
        let vm = QuickConnectHistoryVm::new(Box::new(store)).unwrap();
        assert_eq!(vm.len(), 1);
        assert_eq!(vm.entries()[0].host, "10.0.0.1");
        assert_eq!(vm.entries()[0].port, Some(8443));
        assert_eq!(vm.entries()[0].display_label(), "http 10.0.0.1:8443");
    }

    #[test]
    fn capacity_zero_keeps_empty() {
        let mut vm = QuickConnectHistoryVm::fake_with_capacity(0);
        vm.record_success(ProtocolType::Ssh, "x", None).unwrap();
        assert!(vm.is_empty());
    }

    #[test]
    fn blank_node_host_fail_closed() {
        let mut vm = QuickConnectHistoryVm::fake();
        let node = ConnectionNode {
            id: Uuid::new_v4(),
            kind: NodeKind::Connection,
            protocol: Some(ProtocolType::Ssh),
            host: Some("  ".into()),
            port: Some(22),
            ..ConnectionNode::default()
        };
        assert_eq!(
            vm.record_success_from_node(&node).unwrap_err(),
            QuickConnectHistoryError::EmptyHost
        );
        assert!(vm.is_empty());
    }

    #[test]
    fn reload_persists_capacity_clamp() {
        #[derive(Clone, Default)]
        struct SharedFake(Arc<FakeQuickConnectHistoryStore>);
        impl QuickConnectHistoryStore for SharedFake {
            fn load(&self) -> Result<Vec<QuickConnectHistoryEntry>, QuickConnectHistoryError> {
                self.0.load()
            }
            fn save(
                &self,
                entries: &[QuickConnectHistoryEntry],
            ) -> Result<(), QuickConnectHistoryError> {
                self.0.save(entries)
            }
        }

        let shared = Arc::new(FakeQuickConnectHistoryStore::with_entries(vec![
            QuickConnectHistoryEntry::try_new(ProtocolType::Ssh, "a", Some(2222)).unwrap(),
            QuickConnectHistoryEntry::try_new(ProtocolType::Ssh, "b", Some(2222)).unwrap(),
            QuickConnectHistoryEntry::try_new(ProtocolType::Ssh, "c", Some(2222)).unwrap(),
        ]));
        let mut vm =
            QuickConnectHistoryVm::with_capacity(Box::new(SharedFake(Arc::clone(&shared))), 2)
                .unwrap();
        assert_eq!(vm.len(), 2);
        assert_eq!(shared.snapshot().len(), 2);

        shared
            .save(&[
                QuickConnectHistoryEntry::try_new(ProtocolType::Ssh, "a", Some(2222)).unwrap(),
                QuickConnectHistoryEntry::try_new(ProtocolType::Ssh, "b", Some(2222)).unwrap(),
                QuickConnectHistoryEntry::try_new(ProtocolType::Ssh, "c", Some(2222)).unwrap(),
                QuickConnectHistoryEntry::try_new(ProtocolType::Ssh, "d", Some(2222)).unwrap(),
            ])
            .unwrap();
        vm.reload().unwrap();
        assert_eq!(vm.len(), 2);
        assert_eq!(shared.snapshot().len(), 2);
    }

    #[test]
    fn commit_leaves_memory_untouched_when_store_save_fails() {
        struct ControllableStore {
            inner: Mutex<Vec<QuickConnectHistoryEntry>>,
            fail: AtomicBool,
        }
        impl QuickConnectHistoryStore for ControllableStore {
            fn load(&self) -> Result<Vec<QuickConnectHistoryEntry>, QuickConnectHistoryError> {
                Ok(self.inner.lock().unwrap_or_else(|p| p.into_inner()).clone())
            }
            fn save(
                &self,
                entries: &[QuickConnectHistoryEntry],
            ) -> Result<(), QuickConnectHistoryError> {
                if self.fail.load(Ordering::SeqCst) {
                    return Err(QuickConnectHistoryError::Store("boom".into()));
                }
                *self.inner.lock().unwrap_or_else(|p| p.into_inner()) = entries.to_vec();
                Ok(())
            }
        }

        struct Shared(Arc<ControllableStore>);
        impl QuickConnectHistoryStore for Shared {
            fn load(&self) -> Result<Vec<QuickConnectHistoryEntry>, QuickConnectHistoryError> {
                self.0.load()
            }
            fn save(
                &self,
                entries: &[QuickConnectHistoryEntry],
            ) -> Result<(), QuickConnectHistoryError> {
                self.0.save(entries)
            }
        }

        let store = Arc::new(ControllableStore {
            inner: Mutex::new(vec![QuickConnectHistoryEntry::try_new(
                ProtocolType::Ssh,
                "kept",
                Some(2222),
            )
            .unwrap()]),
            fail: AtomicBool::new(false),
        });

        let mut vm =
            QuickConnectHistoryVm::with_capacity(Box::new(Shared(Arc::clone(&store))), 10).unwrap();
        assert_eq!(vm.len(), 1);

        store.fail.store(true, Ordering::SeqCst);
        let err = vm
            .record_success(ProtocolType::Ssh, "new", Some(2222))
            .unwrap_err();
        assert!(matches!(err, QuickConnectHistoryError::Store(_)));
        assert_eq!(vm.len(), 1);
        assert_eq!(vm.entries()[0].host, "kept");
        assert_eq!(store.load().unwrap().len(), 1);
    }
}
