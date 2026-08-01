//! Live open-tab scanner glue that reconciles the MCP session registry.
//!
//! Mirrors how C# `McpSessionRegistry` discovers sessions in production: it scans
//! the ShellViewModel tab bar (`SshSessionViewModel.IsMcpConnected`), whereas the
//! Lab Fake previously relied on explicit `register` / `unregister`. This scanner
//! closes that gap — the product host supplies a live [`McpOpenTabSource`] (the
//! tab bar) and [`McpLiveTabScanner`] reconciles [`crate::FakeMcpSessionRegistry`]
//! with whatever is currently open + connected.
//!
//! Semantics:
//! - Tabs that are **open and [`McpSessionStatus::Connected`]** are registered
//!   (canonicalized via [`crate::canonicalize_session_id`], deduped, first
//!   occurrence wins).
//! - Ids that are no longer open / connected are **unregistered** (C# leaves only
//!   Connected, `IsMcpConnected`-eligible tabs visible to MCP).
//!
//! Fail-closed map:
//!
//! | Condition | Result |
//! |---|---|
//! | [`McpOpenTabSource`] returns `Err` | scan returns `Err`, **registry unchanged** (no destructive sweep) |
//! | any eligible tab has a blank / control-char id | scan returns `Err`, **registry unchanged** (atomic pre-validation) |
//! | non-Connected tab | skipped (C# `IsMcpConnected` filter), never registered |
//! | duplicate canonical id within one scan | deduped — registered once |
//! | already-registered id | left as-is (no duplicate-register error) |
//! | empty source | no registrations; current ids unregistered (tabs gone / no longer connected) |
//!
//! Deterministic: `scan_and_sync` takes an explicit [`ScanTick`] stamp so tests
//! need no wall clock. [`Debug`] / the scan report carry ids + counts only — never
//! bearer tokens, passwords, or terminal output.

use std::collections::{HashSet, VecDeque};
use std::fmt;
use std::sync::Mutex;

use crate::session_registry::{canonicalize_session_id, FakeMcpSessionRegistry, McpSessionInfo};
use crate::McpError;

/// Deterministic scan tick — the host maps a wall-clock-derived value (C# audit
/// stamps scans); unit tests pass fixed ticks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ScanTick(pub u64);

impl ScanTick {
    /// Construct from an arbitrary tick value.
    pub const fn new(tick: u64) -> Self {
        Self(tick)
    }
}

/// Source of currently-open SSH tabs supplied by the product host (live tab bar).
///
/// The host must yield only the **open and Connected** tabs it wants exposed to
/// MCP (C# scans `Tabs` and filters `SshSessionViewModel.IsMcpConnected`); the
/// scanner still defensively skips any non-Connected row.
pub trait McpOpenTabSource: Send + Sync {
    /// Scan the currently-open MCP-eligible tabs.
    ///
    /// `Err` (e.g. the UI is closing / dispatcher gone) → the scanner fails
    /// closed and leaves the registry untouched.
    fn scan_open_tabs(&self) -> Result<Vec<McpSessionInfo>, McpError>;
}

/// Scripted [`McpOpenTabSource`] for unit tests.
///
/// Each [`Self::push_tabs`] / [`Self::push_err`] queues one scan; the scanner's
/// next [`scan_open_tabs`](McpOpenTabSource::scan_open_tabs) consumes it. An
/// exhausted script fails closed (returns `Err`) rather than silently treating a
/// missing script as "no tabs".
#[derive(Default)]
pub struct FakeMcpOpenTabSource {
    script: Mutex<VecDeque<Result<Vec<McpSessionInfo>, McpError>>>,
}

impl FakeMcpOpenTabSource {
    /// Empty source — every scan fails closed until scripted.
    pub fn new() -> Self {
        Self::default()
    }

    /// Seed with one scan returning the given open tabs.
    pub fn with_tabs(tabs: impl IntoIterator<Item = McpSessionInfo>) -> Self {
        let src = Self::new();
        src.push_tabs(tabs);
        src
    }

    /// Queue one successful scan.
    pub fn push_tabs(&self, tabs: impl IntoIterator<Item = McpSessionInfo>) {
        self.script
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push_back(Ok(tabs.into_iter().collect()));
    }

    /// Queue one failing scan (scanner must no-op on it).
    pub fn push_err(&self, err: McpError) {
        self.script
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push_back(Err(err));
    }

    /// Number of scripted scans still queued.
    pub fn remaining(&self) -> usize {
        self.script.lock().unwrap_or_else(|p| p.into_inner()).len()
    }
}

impl McpOpenTabSource for FakeMcpOpenTabSource {
    fn scan_open_tabs(&self) -> Result<Vec<McpSessionInfo>, McpError> {
        self.script
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .pop_front()
            .unwrap_or_else(|| {
                Err(McpError::Message(
                    "FakeMcpOpenTabSource has no scripted scan left (fail closed)".into(),
                ))
            })
    }
}

impl fmt::Debug for FakeMcpOpenTabSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FakeMcpOpenTabSource")
            .field("script_len", &self.remaining())
            // No id / metadata bodies — ids are the MCP surface, but Debug stays
            // count-only to avoid echoing any tab-derived secrets (none today).
            .finish()
    }
}

/// Outcome of one [`McpLiveTabScanner::scan_and_sync`] reconciliation.
///
/// [`Debug`] prints ids + counts only — no token / password / terminal data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpScanReport {
    pub scanned_at: ScanTick,
    /// Canonical ids newly registered this scan (open, connected, unique).
    pub registered: Vec<String>,
    /// Ids unregistered this scan (no longer open / connected).
    pub unregistered: Vec<String>,
    /// Number of unique open + connected tabs observed.
    pub total_open: usize,
}

/// Reconciles the MCP session registry with the live tab bar.
///
/// Stateless glue — call [`Self::scan_and_sync`] whenever the tab bar changes
/// (tab opened / closed / session connected / disconnected).
#[derive(Clone, Copy, Default)]
pub struct McpLiveTabScanner;

impl McpLiveTabScanner {
    pub fn new() -> Self {
        Self
    }

    /// Reconcile `registry` against `source` at `now`.
    ///
    /// Fail-closed: any source error or any blank / control-char eligible id
    /// aborts the whole scan with the registry untouched (no partial registration
    /// and **no** destructive unregister sweep on error). Otherwise new open ids
    /// are registered first, then stale ids unregistered; the report captures both
    /// sets in deterministic order.
    pub fn scan_and_sync(
        &self,
        registry: &FakeMcpSessionRegistry,
        source: &dyn McpOpenTabSource,
        now: ScanTick,
    ) -> Result<McpScanReport, McpError> {
        // Source error → fail closed; registry completely untouched.
        let tabs = source.scan_open_tabs()?;

        // Phase A — validate + Connected-filter + dedupe, preserving source order.
        // Any invalid eligible id aborts before any mutation (atomic pre-check).
        let mut open: Vec<(String, McpSessionInfo)> = Vec::new();
        let mut seen: HashSet<String> = HashSet::new();
        for tab in tabs {
            if !tab.status.is_connected() {
                continue; // C# IsMcpConnected filter — not MCP-visible.
            }
            let id = canonicalize_session_id(&tab.id)?; // fail closed on blank/control.
            if !seen.insert(id.clone()) {
                continue; // dedupe — first occurrence wins.
            }
            open.push((id, tab));
        }

        // Phase B — diff against the current registry (no mutation).
        let current = registry.registered_ids();
        let open_ids: HashSet<&str> = open.iter().map(|(id, _)| id.as_str()).collect();
        let to_register: Vec<&(String, McpSessionInfo)> = open
            .iter()
            .filter(|(id, _)| !open_ids_contains_id(&current, id))
            .collect();
        let to_unregister: Vec<&str> = current
            .iter()
            .filter(|id| !open_ids.contains(id.as_str()))
            .map(String::as_str)
            .collect();

        // Phase C — apply: register new (Connected + canonical + deduped, so it
        // cannot fail absent a concurrent mutation), then unregister stale.
        let mut registered = Vec::new();
        let mut unregistered = Vec::new();
        for (id, info) in &to_register {
            registry.register(info.clone())?;
            registered.push(id.clone());
        }
        for id in &to_unregister {
            registry.unregister(id)?;
            unregistered.push((*id).to_owned());
        }

        Ok(McpScanReport {
            scanned_at: now,
            registered,
            unregistered,
            total_open: open.len(),
        })
    }
}

fn open_ids_contains_id(current: &[String], id: &str) -> bool {
    current.iter().any(|existing| existing == id)
}

impl fmt::Debug for McpLiveTabScanner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Stateless glue — nothing secret to hide, keep the label stable for Debug tests.
        f.debug_struct("McpLiveTabScanner").finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session_registry::{McpSessionRegistry, McpSessionStatus};

    fn open(id: &str) -> McpSessionInfo {
        McpSessionInfo::connected(id, "host.example", 22, "alice", "prod")
    }

    fn disconnected(id: &str) -> McpSessionInfo {
        McpSessionInfo::new(id, "h", 22, "u", "t", McpSessionStatus::Disconnected)
    }

    #[test]
    fn open_tab_gets_registered_with_metadata() {
        let reg = FakeMcpSessionRegistry::new();
        let source = FakeMcpOpenTabSource::with_tabs([open("s1")]);
        let report = McpLiveTabScanner::new()
            .scan_and_sync(&reg, &source, ScanTick::new(7))
            .unwrap();
        assert_eq!(report.scanned_at, ScanTick::new(7));
        assert_eq!(report.registered, vec!["s1".to_owned()]);
        assert!(report.unregistered.is_empty());
        assert_eq!(report.total_open, 1);

        let listed = reg.list_sessions();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, "s1");
        assert_eq!(listed[0].host, "host.example");
        assert_eq!(listed[0].port, 22);
        assert_eq!(listed[0].username, "alice");
        assert_eq!(listed[0].title, "prod");
        assert_eq!(listed[0].status, McpSessionStatus::Connected);
    }

    #[test]
    fn closed_tab_gets_unregistered() {
        let reg = FakeMcpSessionRegistry::new();
        reg.register(open("s1")).unwrap();
        reg.register(open("s2")).unwrap();
        let source = FakeMcpOpenTabSource::with_tabs([open("s1")]);
        let report = McpLiveTabScanner::new()
            .scan_and_sync(&reg, &source, ScanTick::new(1))
            .unwrap();
        assert!(report.registered.is_empty());
        assert_eq!(report.unregistered, vec!["s2".to_owned()]);
        assert_eq!(report.total_open, 1);
        assert_eq!(reg.list_sessions().len(), 1);
        assert_eq!(reg.list_sessions()[0].id, "s1");
    }

    #[test]
    fn concurrent_ids_register_in_source_order() {
        let reg = FakeMcpSessionRegistry::new();
        let source = FakeMcpOpenTabSource::with_tabs([open("a"), open("b"), open("c")]);
        let report = McpLiveTabScanner::new()
            .scan_and_sync(&reg, &source, ScanTick::new(2))
            .unwrap();
        assert_eq!(report.registered, vec!["a", "b", "c"]);
        assert!(report.unregistered.is_empty());
        assert_eq!(report.total_open, 3);
        let ids: Vec<_> = reg
            .list_sessions()
            .into_iter()
            .map(|s| s.id.clone())
            .collect();
        assert_eq!(ids, vec!["a", "b", "c"]);
    }

    #[test]
    fn empty_source_registers_nothing_and_unregisters_all() {
        let reg = FakeMcpSessionRegistry::new();
        let source = FakeMcpOpenTabSource::with_tabs([]);
        let report = McpLiveTabScanner::new()
            .scan_and_sync(&reg, &source, ScanTick::new(3))
            .unwrap();
        assert!(report.registered.is_empty());
        assert!(report.unregistered.is_empty());
        assert_eq!(report.total_open, 0);
        assert!(reg.is_empty());

        // With existing sessions: empty source means no tabs remain → all unregistered.
        let reg2 = FakeMcpSessionRegistry::new();
        reg2.register(open("a")).unwrap();
        reg2.register(open("b")).unwrap();
        let source2 = FakeMcpOpenTabSource::with_tabs([]);
        let report2 = McpLiveTabScanner::new()
            .scan_and_sync(&reg2, &source2, ScanTick::new(3))
            .unwrap();
        assert!(report2.registered.is_empty());
        assert_eq!(report2.unregistered, vec!["a", "b"]);
        assert!(reg2.is_empty());
    }

    #[test]
    fn source_error_leaves_registry_unchanged() {
        let reg = FakeMcpSessionRegistry::new();
        reg.register(open("s1")).unwrap();
        let source = FakeMcpOpenTabSource::new();
        source.push_err(McpError::Message("UI dispatcher unavailable".into()));

        let err = McpLiveTabScanner::new()
            .scan_and_sync(&reg, &source, ScanTick::new(4))
            .unwrap_err();
        assert!(err.to_string().contains("UI dispatcher"));
        // No destructive sweep: s1 stays, s2 never touched.
        assert_eq!(reg.registered_ids(), vec!["s1".to_owned()]);
        assert_eq!(reg.list_sessions().len(), 1);
    }

    #[test]
    fn dedupe_within_source_registers_once() {
        let reg = FakeMcpSessionRegistry::new();
        let source = FakeMcpOpenTabSource::with_tabs([open("s1"), open("s1"), open("  s1  ")]);
        let report = McpLiveTabScanner::new()
            .scan_and_sync(&reg, &source, ScanTick::new(5))
            .unwrap();
        assert_eq!(report.registered, vec!["s1".to_owned()]);
        assert_eq!(report.total_open, 1);
        assert_eq!(reg.list_sessions().len(), 1);
    }

    #[test]
    fn id_canonicalization_matches_shared_rule() {
        // Padded ids register under the canonical (trimmed) id — parity with
        // `canonicalize_session_id`, which the registry's register also applies.
        let reg = FakeMcpSessionRegistry::new();
        let source = FakeMcpOpenTabSource::with_tabs([open("  sess-1  ")]);
        let report = McpLiveTabScanner::new()
            .scan_and_sync(&reg, &source, ScanTick::new(6))
            .unwrap();
        assert_eq!(report.registered, vec!["sess-1".to_owned()]);
        assert_eq!(reg.registered_ids(), vec!["sess-1".to_owned()]);
        assert_eq!(canonicalize_session_id("  sess-1  ").unwrap(), "sess-1");
    }

    #[test]
    fn invalid_eligible_id_aborts_whole_scan_fail_closed() {
        let reg = FakeMcpSessionRegistry::new();
        reg.register(open("s1")).unwrap();
        // A later, invalid eligible id must abort with NO partial registration and
        // NO unregister sweep despite the valid s1 preceding it.
        let source =
            FakeMcpOpenTabSource::with_tabs([open("s1"), open("bad\nid"), open("s2")]);
        let err = McpLiveTabScanner::new()
            .scan_and_sync(&reg, &source, ScanTick::new(7))
            .unwrap_err();
        assert!(err.to_string().contains("control"));
        assert_eq!(reg.registered_ids(), vec!["s1".to_owned()]);
        assert_eq!(reg.list_sessions().len(), 1);
    }

    #[test]
    fn disconnected_tabs_are_skipped_and_leave_connected_only() {
        // A previously-connected tab that is now Disconnected must be dropped from
        // the registry (C# IsMcpConnected filter), and a never-connected tab must
        // never be registered.
        let reg = FakeMcpSessionRegistry::new();
        reg.register(open("s1")).unwrap();
        reg.register(open("d1")).unwrap(); // was connected, now disconnected below
        let source = FakeMcpOpenTabSource::with_tabs([open("s1"), disconnected("d1")]);
        let report = McpLiveTabScanner::new()
            .scan_and_sync(&reg, &source, ScanTick::new(8))
            .unwrap();
        assert!(report.registered.is_empty(), "already registered");
        assert_eq!(report.unregistered, vec!["d1".to_owned()]);
        // Only Connected rows remain registered — disconnected "d1" dropped.
        assert_eq!(reg.registered_ids(), vec!["s1".to_owned()]);
        assert_eq!(report.total_open, 1, "only the Connected tab counts");
        let listed = reg.list_sessions();
        assert_eq!(listed.len(), 1);
        assert!(listed[0].status.is_connected());
        assert_eq!(listed[0].id, "s1");
    }

    #[test]
    fn exhausted_source_script_fails_closed() {
        let reg = FakeMcpSessionRegistry::new();
        let source = FakeMcpOpenTabSource::new(); // nothing scripted
        let err = McpLiveTabScanner::new()
            .scan_and_sync(&reg, &source, ScanTick::new(9))
            .unwrap_err();
        assert!(err.to_string().contains("no scripted scan left"));
        assert!(reg.is_empty());
    }

    #[test]
    fn re_scan_is_idempotent_and_reregisters_after_reopen() {
        let reg = FakeMcpSessionRegistry::new();
        let source = FakeMcpOpenTabSource::with_tabs([open("s1")]);
        let scanner = McpLiveTabScanner::new();
        scanner.scan_and_sync(&reg, &source, ScanTick::new(1)).unwrap();
        // Same tabs again → nothing new, still registered once. (Script-based
        // fake is single-use, so queue the next scan.)
        source.push_tabs([open("s1")]);
        let report = scanner
            .scan_and_sync(&reg, &source, ScanTick::new(2))
            .unwrap();
        assert!(report.registered.is_empty());
        assert!(report.unregistered.is_empty());
        assert_eq!(reg.list_sessions().len(), 1);

        // Close then reopen: unregister + re-register round trip.
        source.push_tabs([]);
        scanner.scan_and_sync(&reg, &source, ScanTick::new(3)).unwrap();
        assert!(reg.is_empty());
        source.push_tabs([open("s1")]);
        scanner.scan_and_sync(&reg, &source, ScanTick::new(4)).unwrap();
        assert_eq!(reg.registered_ids(), vec!["s1".to_owned()]);
    }

    #[test]
    fn scan_report_is_deterministic_across_runs() {
        // Same input state + same source must produce identical reports on every
        // run (no HashMap iteration order leaks into registered/unregistered).
        let scan = |seed: &[&str], tabs: &[&str]| {
            let reg = FakeMcpSessionRegistry::new();
            for id in seed {
                reg.register(open(id)).unwrap();
            }
            let source = FakeMcpOpenTabSource::with_tabs(tabs.iter().map(|id| open(id)));
            McpLiveTabScanner::new()
                .scan_and_sync(&reg, &source, ScanTick::new(11))
                .map(|report| (report, reg.registered_ids()))
        };

        let (r1, ids1) = scan(&["a", "b", "c"], &["c", "a", "d", "d"]).unwrap();
        let (r2, ids2) = scan(&["a", "b", "c"], &["c", "a", "d", "d"]).unwrap();
        assert_eq!(r1.registered, vec!["d".to_owned()]);
        assert_eq!(r1.unregistered, vec!["b".to_owned()]);
        assert_eq!(r1.total_open, 3);
        assert_eq!(r1, r2);
        assert_eq!(ids1, ids2);
        assert_eq!(ids1, vec!["a".to_owned(), "c".to_owned(), "d".to_owned()]);
    }

    #[test]
    fn disconnected_tab_with_invalid_id_is_skipped_not_abort() {
        // Only *eligible* (Connected) ids are pre-validated; a closed tab with a
        // blank/control id must not fail the whole scan (C# IsMcpConnected filter).
        let reg = FakeMcpSessionRegistry::new();
        reg.register(open("s1")).unwrap();
        let source = FakeMcpOpenTabSource::with_tabs([
            open("s1"),
            disconnected(""),
            disconnected("bad\nid"),
        ]);
        let report = McpLiveTabScanner::new()
            .scan_and_sync(&reg, &source, ScanTick::new(12))
            .unwrap();
        assert!(report.registered.is_empty());
        assert!(report.unregistered.is_empty());
        assert_eq!(report.total_open, 1);
        assert_eq!(reg.registered_ids(), vec!["s1".to_owned()]);
    }

    #[test]
    fn padded_open_id_matches_already_registered_canonical_id() {
        // Registry already holds the canonical id; a padded source id is the same
        // session (shared canonicalize rule) — no duplicate-register, no sweep.
        let reg = FakeMcpSessionRegistry::new();
        reg.register(open("s1")).unwrap();
        let source = FakeMcpOpenTabSource::with_tabs([open("  s1  ")]);
        let report = McpLiveTabScanner::new()
            .scan_and_sync(&reg, &source, ScanTick::new(13))
            .unwrap();
        assert!(report.registered.is_empty());
        assert!(report.unregistered.is_empty());
        assert_eq!(report.total_open, 1);
        assert_eq!(reg.registered_ids(), vec!["s1".to_owned()]);
        assert_eq!(reg.list_sessions().len(), 1);
    }

    #[test]
    fn debug_and_reports_omit_token_wording_and_secrets() {
        let scanner = McpLiveTabScanner::new();
        let s = format!("{scanner:?}");
        assert!(s.contains("McpLiveTabScanner"));
        assert!(!s.to_ascii_lowercase().contains("bearer"));
        assert!(!s.to_ascii_lowercase().contains("token"));

        let src = FakeMcpOpenTabSource::with_tabs([open("s1")]);
        let s = format!("{src:?}");
        assert!(s.contains("script_len"));
        assert!(!s.to_ascii_lowercase().contains("bearer"));
        assert!(!s.to_ascii_lowercase().contains("token"));
        assert!(!s.contains("password"));

        let reg = FakeMcpSessionRegistry::new();
        let report = McpLiveTabScanner::new()
            .scan_and_sync(&reg, &src, ScanTick::new(10))
            .unwrap();
        let rd = format!("{report:?}");
        assert!(rd.contains("registered"));
        assert!(!rd.to_ascii_lowercase().contains("bearer"));
        assert!(!rd.to_ascii_lowercase().contains("token"));
        assert!(!rd.contains("password"));
    }
}
