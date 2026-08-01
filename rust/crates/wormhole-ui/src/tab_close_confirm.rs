//! Tab close-confirm Lab glue — no GPUI / ContentDialog chrome.
//!
//! Pure state VM (`TabCloseConfirmVm`) + injectable confirm renderer
//! ([`TabCloseConfirmUi`]) for the "Shell | Tabbed sessions + close confirm" gap.
//! C# parity notes:
//! - per-tab close (`SessionsPage.CloseTabAsync` / `SessionTabs_TabCloseRequested`):
//!   only tabs whose session would actually be torn down need confirmation —
//!   [`SessionTabViewModel.WillDisconnectOnAppClose`] (status Connected / Connecting).
//!   Already-disconnected tabs close immediately without prompting.
//! - app close (`MainWindow.OnClosing`): `ActiveSessionCount` is snapshotted **once**;
//!   a single `IDialogService.ConfirmAsync` covers the whole window; when the prompt
//!   cannot be shown (exception) C# treats it as `confirmed = false` and leaves the
//!   window open. Confirm → `CloseAllSessionsAsync` closes every tab.
//! [`request_close`](TabCloseConfirmVm::request_close) never blocks (the C# prompt is
//! async and outlives the request); the host resolves later via
//! [`confirm`](TabCloseConfirmVm::confirm) / [`cancel`](TabCloseConfirmVm::cancel)
//! (or [`confirm_all`](TabCloseConfirmVm::confirm_all) /
//! [`cancel_all`](TabCloseConfirmVm::cancel_all) for the batch path). The renderer
//! trait is fire-and-forget: `show` failing (UI unreachable) drops the request and the
//! tab stays open.
//!
//! Fail-closed map:
//!
//! | Condition | Result |
//! |---|---|
//! | `request_close` with `will_disconnect == false` (disconnected tab) | close immediately, no prompt |
//! | `request_close` / `request_close_all` for an id already pending | no-op (`AlreadyPending`) |
//! | `request_close_all` batch whose ids would bypass an outstanding confirmation | rejected whole (`AlreadyPending`) |
//! | `request_close_all` zero-disconnect batch (closes every tab) while any confirmation is outstanding | rejected whole (`AlreadyPending`) |
//! | duplicate ids inside a `request_close_all` batch | collapsed to one entry per tab |
//! | `show` renderer returns `false` (UI unreachable / channel abandoned) | request dropped, tab stays open |
//! | `confirm` / `cancel` for unknown or non-pending id | no-op (`false`) |
//! | `confirm` / `cancel` after the entry was already resolved (already-closed tab) | no-op (`false`) |
//! | `confirm` / `cancel` for a tab inside a pending batch | no-op — batch resolves only via `confirm_all` / `cancel_all` |
//! | user Cancel / prompt error | tab stays open (**fail closed**) |
//! | `confirm_all` / `cancel_all` | whole pending set resolves atomically |
//!
//! This module holds no secrets — [`Debug`] surfaces tab ids + pending counts only.

use std::fmt;
use std::sync::mpsc;

use crate::session_tab_bar::SessionId;

/// What the confirm surface should render (C# `IDialogService.ConfirmAsync(title, message)`).
///
/// `ids` lists the tabs whose close is being asked about (length 1 = single close,
/// length > 1 = batch); `will_disconnect` is how many of them hold a live session that
/// closing would tear down — the "N connections are still open" message payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TabCloseConfirmRequest {
    /// Tabs whose close is pending confirmation (non-empty).
    pub ids: Vec<SessionId>,
    /// Of `ids`, how many would disconnect if closed (prompt severity).
    pub will_disconnect: usize,
}

impl TabCloseConfirmRequest {
    /// Single-tab close request (the tab would disconnect).
    pub fn single(id: SessionId) -> Self {
        Self {
            ids: vec![id],
            will_disconnect: 1,
        }
    }

    /// Batch close request. `will_disconnect` is clamped to `ids.len()`.
    pub fn batch(ids: Vec<SessionId>, will_disconnect: usize) -> Self {
        let will_disconnect = will_disconnect.min(ids.len());
        Self {
            ids,
            will_disconnect,
        }
    }
}

/// Outcome of [`TabCloseConfirmVm::request_close`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseRequestOutcome {
    /// Prompt shown; entry recorded — resolve with `confirm` / `cancel`.
    Pending,
    /// Tab would not disconnect — closed immediately without prompting.
    Closed,
    /// Tab already pending — nothing recorded (duplicate request).
    AlreadyPending,
    /// Confirm surface unreachable — request dropped, tab stays open (fail closed).
    PromptFailed,
}

/// Outcome of [`TabCloseConfirmVm::request_close_all`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseAllOutcome {
    /// Prompt shown; whole batch recorded — resolve with `confirm_all` / `cancel_all`.
    Pending,
    /// Nothing would disconnect — close every tab immediately, no prompt.
    Closed,
    /// No ids supplied — no-op.
    Empty,
    /// At least one id already pending — whole batch rejected (atomic); also
    /// returned when the batch would close every tab without prompting while *any*
    /// confirmation is still outstanding.
    AlreadyPending,
    /// Confirm surface unreachable — batch dropped, tabs stay open (fail closed).
    PromptFailed,
}

/// Confirm-prompt renderer seam (tests: [`FakeTabCloseConfirmUi`];
/// host: [`ChannelTabCloseConfirmUi`]).
///
/// The VM calls [`show`](TabCloseConfirmUi::show) after recording a pending close; the
/// answer flows back through [`TabCloseConfirmVm::confirm`] / [`cancel`] /
/// [`confirm_all`](TabCloseConfirmVm::confirm_all) /
/// [`cancel_all`](TabCloseConfirmVm::cancel_all). Renderers never decide — returning
/// `false` (unreachable surface) only drops the request, fail closed.
pub trait TabCloseConfirmUi: Send + Sync {
    /// Render the prompt for `request`. `false` = the surface could not be reached;
    /// the VM then drops the request and the tab stays open.
    fn show(&self, request: &TabCloseConfirmRequest) -> bool;
}

/// Scripted confirm renderer for unit tests (no GPUI).
///
/// Records every shown request. Never answers — resolution is exercised through
/// [`TabCloseConfirmVm::confirm`] / [`cancel`] (see tests).
///
/// [`Debug`] exposes show counts + recorded tab ids only.
#[derive(Default)]
pub struct FakeTabCloseConfirmUi {
    shown: std::sync::Mutex<Vec<TabCloseConfirmRequest>>,
    show_calls: std::sync::atomic::AtomicUsize,
}

impl fmt::Debug for FakeTabCloseConfirmUi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let shown = self.shown.lock().unwrap_or_else(|p| p.into_inner());
        f.debug_struct("FakeTabCloseConfirmUi")
            .field("show_calls", &self.show_calls.load(std::sync::atomic::Ordering::SeqCst))
            .field("shown", &shown)
            .finish()
    }
}

impl FakeTabCloseConfirmUi {
    /// Empty recorder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of `show` calls.
    pub fn show_calls(&self) -> usize {
        self.show_calls.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Every request shown so far, in order.
    pub fn shown_requests(&self) -> Vec<TabCloseConfirmRequest> {
        self.shown.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }

    /// Most recent shown request.
    pub fn last_request(&self) -> Option<TabCloseConfirmRequest> {
        self.shown_requests().pop()
    }
}

impl TabCloseConfirmUi for FakeTabCloseConfirmUi {
    fn show(&self, request: &TabCloseConfirmRequest) -> bool {
        self.show_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.shown.lock().unwrap_or_else(|p| p.into_inner()).push(request.clone());
        true
    }
}

/// [`TabCloseConfirmUi`] for a shared Fake handle.
impl TabCloseConfirmUi for std::sync::Arc<FakeTabCloseConfirmUi> {
    fn show(&self, request: &TabCloseConfirmRequest) -> bool {
        (**self).show(request)
    }
}

/// Channel-backed confirm renderer (mirrors the `OtpPromptChannel` shape).
///
/// [`show`](TabCloseConfirmUi::show) posts the request to an unbounded std channel; the
/// host drains [`pending_rx`](TabCloseConfirmChannel::pending_rx) and resolves through
/// the VM's `confirm` / `cancel` / `confirm_all` / `cancel_all`. Dropped / never-opened
/// receiver → `show` returns `false` (fail closed).
#[derive(Clone)]
pub struct ChannelTabCloseConfirmUi {
    tx: mpsc::Sender<TabCloseConfirmRequest>,
}

impl fmt::Debug for ChannelTabCloseConfirmUi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChannelTabCloseConfirmUi")
            .field("tx", &"<mpsc>")
            .finish()
    }
}

impl TabCloseConfirmUi for ChannelTabCloseConfirmUi {
    fn show(&self, request: &TabCloseConfirmRequest) -> bool {
        self.tx.send(request.clone()).is_ok()
    }
}

/// Open channel pair: inject [`ui`](TabCloseConfirmChannel::ui) into the VM and drain
/// [`pending_rx`](TabCloseConfirmChannel::pending_rx) on the host side.
pub struct TabCloseConfirmChannel {
    ui: ChannelTabCloseConfirmUi,
    pending_rx: mpsc::Receiver<TabCloseConfirmRequest>,
}

impl TabCloseConfirmChannel {
    /// Create a channel-backed renderer and arm the host receiver.
    pub fn open() -> Self {
        let (tx, pending_rx) = mpsc::channel();
        Self {
            ui: ChannelTabCloseConfirmUi { tx },
            pending_rx,
        }
    }

    /// Cloneable renderer handle (inject into [`TabCloseConfirmVm::new`]).
    pub fn ui(&self) -> ChannelTabCloseConfirmUi {
        self.ui.clone()
    }

    /// Host-facing pending queue (one [`TabCloseConfirmRequest`] per `show`).
    pub fn pending_rx(&mut self) -> &mut mpsc::Receiver<TabCloseConfirmRequest> {
        &mut self.pending_rx
    }

    /// Detach the renderer while keeping the receiver.
    pub fn into_parts(
        self,
    ) -> (
        ChannelTabCloseConfirmUi,
        mpsc::Receiver<TabCloseConfirmRequest>,
    ) {
        (self.ui, self.pending_rx)
    }
}

impl fmt::Debug for TabCloseConfirmChannel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TabCloseConfirmChannel")
            .field("ui", &self.ui)
            .field("pending_rx", &"<mpsc>")
            .finish()
    }
}

/// How a pending close entry is keyed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PendingCloseKind {
    /// Per-tab close — resolvable via `confirm` / `cancel`.
    Single,
    /// Member of a `CloseAllSessionsAsync`-style batch — resolvable only via
    /// `confirm_all` / `cancel_all` (atomic unit).
    Batch,
}

/// Tracks the set of tabs pending close confirmation (C# close-confirm state).
///
/// Insertion-ordered (first pending wins for duplicates); `Debug` shows tab ids +
/// pending kinds/counts only — no user content, no secrets.
pub struct TabCloseConfirmVm {
    pending: Vec<(SessionId, PendingCloseKind)>,
    ui: Box<dyn TabCloseConfirmUi>,
}

impl fmt::Debug for TabCloseConfirmVm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TabCloseConfirmVm")
            .field("pending", &self.pending)
            .field("ui", &"<TabCloseConfirmUi>")
            .finish()
    }
}

impl TabCloseConfirmVm {
    /// VM with an injectable confirm renderer.
    pub fn new(ui: Box<dyn TabCloseConfirmUi>) -> Self {
        Self {
            pending: Vec::new(),
            ui,
        }
    }

    /// Any tab pending confirmation?
    pub fn has_pending(&self) -> bool {
        !self.pending.is_empty()
    }

    /// Number of pending close entries (single and batch members alike).
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Is `tab_id` awaiting confirmation?
    pub fn is_pending(&self, tab_id: SessionId) -> bool {
        self.index_of(tab_id).is_some()
    }

    /// Request closing one tab (mirrors `SessionsPage.CloseTabAsync`).
    ///
    /// `will_disconnect` mirrors `SessionTabViewModel.WillDisconnectOnAppClose` (status
    /// Connected / Connecting): `false` closes immediately without prompting. A pending
    /// entry whose session died meanwhile is resolved (stale close no longer needs
    /// confirmation — C# reads `WillDisconnectOnAppClose` at close time).
    pub fn request_close(
        &mut self,
        tab_id: SessionId,
        will_disconnect: bool,
    ) -> CloseRequestOutcome {
        if let Some(idx) = self.index_of(tab_id) {
            if will_disconnect {
                return CloseRequestOutcome::AlreadyPending;
            }
            self.pending.remove(idx);
            return CloseRequestOutcome::Closed;
        }
        if !will_disconnect {
            return CloseRequestOutcome::Closed;
        }
        if self.ui.show(&TabCloseConfirmRequest::single(tab_id)) {
            self.pending
                .push((tab_id, PendingCloseKind::Single));
            CloseRequestOutcome::Pending
        } else {
            CloseRequestOutcome::PromptFailed
        }
    }

    /// Request closing every tab (mirrors `MainWindow.OnClosing` →
    /// `CloseAllSessionsAsync`): one snapshot of how many would disconnect decides
    /// whether a prompt is warranted. Whole batch records atomically — any already
    /// pending id rejects the entire request, and a batch whose close would bypass an
    /// outstanding confirmation is rejected too (fail closed): per-id when the batch
    /// would record its own prompt, global when nothing would disconnect (the batch
    /// then closes *every* tab, so **any** pending confirmation blocks it). Duplicate
    /// ids inside the batch are collapsed to one entry per tab (a repeated id must
    /// not record two pending entries for the same tab).
    pub fn request_close_all(
        &mut self,
        ids: &[SessionId],
        will_disconnect: usize,
    ) -> CloseAllOutcome {
        if ids.is_empty() {
            return CloseAllOutcome::Empty;
        }
        let mut unique = Vec::with_capacity(ids.len());
        for id in ids {
            if !unique.contains(id) {
                unique.push(*id);
            }
        }
        if unique.iter().any(|id| self.index_of(*id).is_some()) {
            return CloseAllOutcome::AlreadyPending;
        }
        if will_disconnect == 0 {
            if self.has_pending() {
                // Closing everything would tear down a tab whose own confirmation is
                // still outstanding, so the zero-disconnect shortcut is refused.
                return CloseAllOutcome::AlreadyPending;
            }
            return CloseAllOutcome::Closed;
        }
        let will_disconnect = will_disconnect.min(unique.len());
        if self.ui.show(&TabCloseConfirmRequest::batch(unique.clone(), will_disconnect)) {
            self.pending
                .extend(unique.into_iter().map(|id| (id, PendingCloseKind::Batch)));
            CloseAllOutcome::Pending
        } else {
            CloseAllOutcome::PromptFailed
        }
    }

    /// Confirm closing `tab_id` (user clicked Confirm on a single-tab prompt).
    ///
    /// `true` when a single-tab entry was resolved (host closes the tab). Unknown,
    /// already-resolved, or batch-member ids are no-ops (`false`, fail closed).
    pub fn confirm(&mut self, tab_id: SessionId) -> bool {
        self.resolve(tab_id)
    }

    /// Cancel closing `tab_id` (user dismissed a single-tab prompt).
    ///
    /// `true` when a single-tab entry was resolved and the tab stays open. Unknown,
    /// already-resolved, or batch-member ids are no-ops (`false`, fail closed).
    pub fn cancel(&mut self, tab_id: SessionId) -> bool {
        self.resolve(tab_id)
    }

    /// Confirm closing everything pending (app-close confirm) — resolves the whole
    /// pending set atomically. Returns the number of entries resolved.
    pub fn confirm_all(&mut self) -> usize {
        self.clear_all()
    }

    /// Cancel closing everything pending (app-close cancel) — resolves the whole
    /// pending set atomically, every tab stays open. Returns the number of entries
    /// resolved.
    pub fn cancel_all(&mut self) -> usize {
        self.clear_all()
    }

    fn index_of(&self, tab_id: SessionId) -> Option<usize> {
        self.pending.iter().position(|(id, _)| *id == tab_id)
    }

    fn resolve(&mut self, tab_id: SessionId) -> bool {
        let Some(idx) = self.index_of(tab_id) else {
            return false;
        };
        if self.pending[idx].1 == PendingCloseKind::Batch {
            return false;
        }
        self.pending.remove(idx);
        true
    }

    fn clear_all(&mut self) -> usize {
        let resolved = self.pending.len();
        self.pending.clear();
        resolved
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn sid() -> SessionId {
        SessionId::new()
    }

    fn vm_with_fake(fake: &Arc<FakeTabCloseConfirmUi>) -> TabCloseConfirmVm {
        TabCloseConfirmVm::new(Box::new(Arc::clone(fake)))
    }

    #[test]
    fn single_confirm_path_via_fake_ui() {
        let fake = Arc::new(FakeTabCloseConfirmUi::new());
        let mut vm = vm_with_fake(&fake);
        let id = sid();

        assert_eq!(vm.request_close(id, true), CloseRequestOutcome::Pending);
        assert_eq!(fake.show_calls(), 1);
        assert_eq!(fake.last_request(), Some(TabCloseConfirmRequest::single(id)));
        assert!(vm.is_pending(id));
        assert_eq!(vm.pending_count(), 1);

        assert!(vm.confirm(id));
        assert!(!vm.has_pending());
        assert_eq!(vm.pending_count(), 0);
        // Closing an already-closed tab is a no-op.
        assert!(!vm.confirm(id));
    }

    #[test]
    fn single_cancel_path_via_fake_ui_fail_closed() {
        let fake = Arc::new(FakeTabCloseConfirmUi::new());
        let mut vm = vm_with_fake(&fake);
        let id = sid();

        assert_eq!(vm.request_close(id, true), CloseRequestOutcome::Pending);
        assert!(vm.cancel(id));
        assert!(!vm.has_pending());
        // Tab stays open — a later close re-prompts instead of silently closing.
        assert_eq!(vm.request_close(id, true), CloseRequestOutcome::Pending);
        assert!(vm.cancel(id));
        assert!(!vm.has_pending());
        assert_eq!(fake.show_calls(), 2);
    }

    #[test]
    fn disconnected_tab_closes_without_prompt() {
        let fake = Arc::new(FakeTabCloseConfirmUi::new());
        let mut vm = vm_with_fake(&fake);
        let id = sid();

        assert_eq!(vm.request_close(id, false), CloseRequestOutcome::Closed);
        assert_eq!(fake.show_calls(), 0, "no prompt for a disconnected tab");
        assert!(!vm.has_pending());
        assert!(!vm.confirm(id));
    }

    #[test]
    fn stale_pending_resolved_when_tab_disconnects() {
        let fake = Arc::new(FakeTabCloseConfirmUi::new());
        let mut vm = vm_with_fake(&fake);
        let id = sid();

        assert_eq!(vm.request_close(id, true), CloseRequestOutcome::Pending);
        // Session died while the prompt was up — C# reads WillDisconnectOnAppClose at
        // close time, so the stale pending entry resolves and the tab closes cleanly.
        assert_eq!(vm.request_close(id, false), CloseRequestOutcome::Closed);
        assert!(!vm.has_pending());
        assert_eq!(fake.show_calls(), 1, "no second prompt");
        assert!(!vm.confirm(id));
    }

    #[test]
    fn duplicate_request_is_noop() {
        let fake = Arc::new(FakeTabCloseConfirmUi::new());
        let mut vm = vm_with_fake(&fake);
        let id = sid();

        assert_eq!(vm.request_close(id, true), CloseRequestOutcome::Pending);
        assert_eq!(
            vm.request_close(id, true),
            CloseRequestOutcome::AlreadyPending
        );
        assert_eq!(fake.show_calls(), 1, "one prompt per tab");
        assert_eq!(vm.pending_count(), 1);
        assert!(vm.confirm(id));
    }

    #[test]
    fn unknown_and_already_closed_resolution_fail_closed() {
        let fake = Arc::new(FakeTabCloseConfirmUi::new());
        let mut vm = vm_with_fake(&fake);
        let missing = sid();

        assert!(!vm.confirm(missing));
        assert!(!vm.cancel(missing));
        assert!(!vm.has_pending());
        assert_eq!(vm.pending_count(), 0);

        let id = sid();
        assert_eq!(vm.request_close(id, true), CloseRequestOutcome::Pending);
        assert!(vm.confirm(id));
        assert!(!vm.confirm(id), "already-resolved entry is a no-op");
        assert!(!vm.cancel(id));
        assert_eq!(vm.pending_count(), 0);
    }

    #[test]
    fn batch_close_confirm_all_atomically() {
        let fake = Arc::new(FakeTabCloseConfirmUi::new());
        let mut vm = vm_with_fake(&fake);
        let a = sid();
        let b = sid();
        let c = sid();
        let ids = [a, b, c];

        assert_eq!(
            vm.request_close_all(&ids, 3),
            CloseAllOutcome::Pending
        );
        assert_eq!(
            fake.last_request(),
            Some(TabCloseConfirmRequest::batch(ids.to_vec(), 3))
        );
        assert_eq!(vm.pending_count(), 3);

        assert_eq!(vm.confirm_all(), 3, "whole set resolves atomically");
        assert!(!vm.has_pending());
        assert!(!vm.confirm(a), "nothing left to confirm");
    }

    #[test]
    fn batch_close_cancel_all_atomically() {
        let fake = Arc::new(FakeTabCloseConfirmUi::new());
        let mut vm = vm_with_fake(&fake);
        let ids = [sid(), sid(), sid(), sid()];

        assert_eq!(vm.request_close_all(&ids, 2), CloseAllOutcome::Pending);
        assert_eq!(
            fake.last_request().unwrap().will_disconnect,
            2,
            "prompt severity mirrors the ActiveSessionCount snapshot"
        );

        assert_eq!(vm.cancel_all(), 4);
        assert!(!vm.has_pending());
        // Every tab stays open — re-requesting still prompts.
        assert_eq!(vm.request_close_all(&ids, 4), CloseAllOutcome::Pending);
        assert_eq!(vm.confirm_all(), 4);
    }

    #[test]
    fn batch_with_nothing_to_disconnect_closes_immediately() {
        let fake = Arc::new(FakeTabCloseConfirmUi::new());
        let mut vm = vm_with_fake(&fake);
        let ids = [sid(), sid()];

        assert_eq!(
            vm.request_close_all(&ids, 0),
            CloseAllOutcome::Closed,
            "a window full of disconnected tabs has nothing to lose"
        );
        assert_eq!(fake.show_calls(), 0);
        assert!(!vm.has_pending());
    }

    #[test]
    fn empty_batch_is_noop() {
        let fake = Arc::new(FakeTabCloseConfirmUi::new());
        let mut vm = vm_with_fake(&fake);

        assert_eq!(vm.request_close_all(&[], 0), CloseAllOutcome::Empty);
        assert_eq!(vm.request_close_all(&[], 3), CloseAllOutcome::Empty);
        assert_eq!(fake.show_calls(), 0);
        assert!(!vm.has_pending());
    }

    #[test]
    fn batch_rejected_whole_when_any_id_pending() {
        let fake = Arc::new(FakeTabCloseConfirmUi::new());
        let mut vm = vm_with_fake(&fake);
        let a = sid();
        let b = sid();

        assert_eq!(vm.request_close(a, true), CloseRequestOutcome::Pending);
        assert_eq!(
            vm.request_close_all(&[a, b], 2),
            CloseAllOutcome::AlreadyPending,
            "atomic batch must not partially merge"
        );
        assert_eq!(fake.show_calls(), 1);
        assert_eq!(vm.pending_count(), 1, "nothing recorded from the rejected batch");
        assert!(!vm.is_pending(b));
    }

    #[test]
    fn batch_with_duplicate_ids_records_each_tab_once() {
        let fake = Arc::new(FakeTabCloseConfirmUi::new());
        let mut vm = vm_with_fake(&fake);
        let a = sid();

        assert_eq!(
            vm.request_close_all(&[a, a], 2),
            CloseAllOutcome::Pending,
            "a repeated tab id still prompts once, for the one tab"
        );
        assert_eq!(
            fake.last_request(),
            Some(TabCloseConfirmRequest::batch(vec![a], 1)),
            "duplicate collapsed; severity clamped to the unique id count"
        );
        assert_eq!(vm.pending_count(), 1, "one pending entry per tab, never two");
        assert!(vm.is_pending(a));
        assert_eq!(vm.confirm_all(), 1);
        assert!(!vm.has_pending());

        // A fresh request afterwards behaves like a normal tab.
        assert_eq!(vm.request_close_all(&[a], 1), CloseAllOutcome::Pending);
        assert_eq!(vm.confirm_all(), 1);
    }

    #[test]
    fn batch_zero_disconnect_does_not_bypass_pending_confirmation() {
        let fake = Arc::new(FakeTabCloseConfirmUi::new());
        let mut vm = vm_with_fake(&fake);
        let a = sid();

        assert_eq!(vm.request_close(a, true), CloseRequestOutcome::Pending);
        // The batch snapshot claims nothing would disconnect, but tab `a` is still
        // awaiting its own confirmation — the batch must not close it out from under
        // that prompt.
        assert_eq!(
            vm.request_close_all(&[a], 0),
            CloseAllOutcome::AlreadyPending,
            "pending confirmation wins over the zero-disconnect shortcut"
        );
        assert_eq!(fake.show_calls(), 1, "no second prompt, nothing recorded");
        assert!(vm.is_pending(a));
        assert!(vm.confirm(a));
        assert!(!vm.has_pending());

        // The global gate: a zero-disconnect batch closes *every* tab, so even a
        // pending confirmation for a tab outside the batch must block it.
        let other = sid();
        assert_eq!(vm.request_close(other, true), CloseRequestOutcome::Pending);
        assert_eq!(
            vm.request_close_all(&[sid()], 0),
            CloseAllOutcome::AlreadyPending,
            "an unrelated outstanding confirmation blocks the close-everything shortcut"
        );
        assert!(vm.is_pending(other));
        assert!(vm.cancel(other));
        assert!(!vm.has_pending());

        // With nothing pending, the shortcut is back in force.
        assert_eq!(
            vm.request_close_all(&[sid()], 0),
            CloseAllOutcome::Closed
        );
    }

    #[test]
    fn two_disjoint_batches_coexist_and_resolve_atomically() {
        let fake = Arc::new(FakeTabCloseConfirmUi::new());
        let mut vm = vm_with_fake(&fake);
        let a = sid();
        let b = sid();

        assert_eq!(vm.request_close_all(&[a, b], 2), CloseAllOutcome::Pending);
        // A second app-close-style request over a *different* set prompts separately...
        let c = sid();
        assert_eq!(vm.request_close_all(&[c], 1), CloseAllOutcome::Pending);
        // ...but never without resolving the outstanding batch first.
        assert_eq!(
            vm.request_close_all(&[c], 0),
            CloseAllOutcome::AlreadyPending,
            "a second close-everything request waits for the first prompt"
        );
        assert_eq!(fake.show_calls(), 2);
        assert_eq!(vm.pending_count(), 3);
        assert_eq!(vm.confirm_all(), 3, "both batches resolve atomically together");
        assert!(!vm.has_pending());
    }

    #[test]
    fn batch_member_stale_disconnect_removes_member_only() {
        let fake = Arc::new(FakeTabCloseConfirmUi::new());
        let mut vm = vm_with_fake(&fake);
        let a = sid();
        let b = sid();

        assert_eq!(vm.request_close_all(&[a, b], 2), CloseAllOutcome::Pending);
        // `a` died while the batch prompt was up: re-requesting its close with
        // will_disconnect == false resolves just that member (C# reads
        // WillDisconnectOnAppClose at close time) and the tab closes cleanly.
        assert_eq!(vm.request_close(a, false), CloseRequestOutcome::Closed);
        assert!(!vm.is_pending(a));
        assert_eq!(vm.pending_count(), 1, "batch keeps only the still-live member");
        assert_eq!(vm.confirm_all(), 1);
        assert!(!vm.has_pending());

        // A freshly requested close for `a` (still open, never confirmed) prompts anew.
        assert_eq!(vm.request_close(a, true), CloseRequestOutcome::Pending);
        assert_eq!(fake.show_calls(), 2);
        assert!(vm.cancel(a));
        assert!(!vm.has_pending());
    }

    #[test]
    fn batch_members_reject_per_id_resolution() {
        let fake = Arc::new(FakeTabCloseConfirmUi::new());
        let mut vm = vm_with_fake(&fake);
        let a = sid();
        let b = sid();

        assert_eq!(vm.request_close_all(&[a, b], 2), CloseAllOutcome::Pending);
        assert!(!vm.confirm(a), "batch resolves only via confirm_all");
        assert!(!vm.cancel(b));
        assert_eq!(vm.pending_count(), 2, "batch untouched by per-id resolution");

        // A tab outside the batch can still prompt independently (mixed state allowed).
        let extra = sid();
        assert_eq!(vm.request_close(extra, true), CloseRequestOutcome::Pending);
        assert!(vm.confirm(extra));
        assert_eq!(vm.pending_count(), 2);
        assert_eq!(vm.confirm_all(), 2);
        assert!(!vm.has_pending());
    }

    #[test]
    fn prompt_failure_drops_request_fail_closed() {
        let (ui, rx) = TabCloseConfirmChannel::open().into_parts();
        drop(rx); // host never drains — surface unreachable
        let mut vm = TabCloseConfirmVm::new(Box::new(ui));
        let id = sid();

        assert_eq!(
            vm.request_close(id, true),
            CloseRequestOutcome::PromptFailed,
            "unreachable UI never leaves a pending entry"
        );
        assert!(!vm.has_pending());
        assert!(!vm.confirm(id));

        let ids = [sid(), sid()];
        assert_eq!(
            vm.request_close_all(&ids, 2),
            CloseAllOutcome::PromptFailed
        );
        assert!(!vm.has_pending());
    }

    #[test]
    fn debug_redaction_shows_ids_and_counts_only() {
        let fake = Arc::new(FakeTabCloseConfirmUi::new());
        let mut vm = vm_with_fake(&fake);
        let a = sid();
        let b = sid();
        let c = sid();

        assert_eq!(vm.request_close(a, true), CloseRequestOutcome::Pending);
        assert_eq!(vm.request_close_all(&[b, c], 1), CloseAllOutcome::Pending);

        let vm_dbg = format!("{vm:?}");
        assert!(vm_dbg.contains(&a.to_string()), "{vm_dbg}");
        assert!(vm_dbg.contains(&b.to_string()), "{vm_dbg}");
        assert!(vm_dbg.contains(&c.to_string()), "{vm_dbg}");
        assert!(vm_dbg.contains("Single"), "{vm_dbg}");
        assert!(vm_dbg.contains("Batch"), "{vm_dbg}");
        assert!(vm_dbg.contains("pending"), "{vm_dbg}");
        assert!(!vm_dbg.contains("<TabCloseConfirmUi>0"), "{vm_dbg}");
        assert!(!vm_dbg.contains("secret"), "{vm_dbg}");

        let fake_dbg = format!("{fake:?}");
        assert!(fake_dbg.contains(&a.to_string()), "{fake_dbg}");
        assert!(fake_dbg.contains("show_calls"), "{fake_dbg}");
        assert!(!fake_dbg.contains("secret"), "{fake_dbg}");
    }

    #[test]
    fn channel_round_trip_through_vm() {
        let (ui, rx) = TabCloseConfirmChannel::open().into_parts();
        let mut vm = TabCloseConfirmVm::new(Box::new(ui));
        let id = sid();

        assert_eq!(vm.request_close(id, true), CloseRequestOutcome::Pending);
        let shown = rx.try_recv().expect("host sees the request");
        assert_eq!(shown, TabCloseConfirmRequest::single(id));

        assert!(vm.confirm(id), "host resolves via the VM");
        assert_eq!(vm.pending_count(), 0);
        assert!(!vm.cancel(id));
        assert!(rx.try_recv().is_err(), "no further requests after resolution");

        // Batch path round-trips the full id list + disconnect snapshot.
        let ids = [sid(), sid()];
        assert_eq!(vm.request_close_all(&ids, 2), CloseAllOutcome::Pending);
        let shown_batch = rx.try_recv().expect("host sees the batch");
        assert_eq!(shown_batch, TabCloseConfirmRequest::batch(ids.to_vec(), 2));
        assert_eq!(vm.cancel_all(), 2);
    }

    #[test]
    fn hostile_batch_disconnect_count_is_clamped() {
        let (ui, rx) = TabCloseConfirmChannel::open().into_parts();
        let mut vm = TabCloseConfirmVm::new(Box::new(ui));
        let ids = [sid()];

        assert_eq!(vm.request_close_all(&ids, usize::MAX), CloseAllOutcome::Pending);
        let shown = rx.try_recv().unwrap();
        assert_eq!(shown.will_disconnect, 1, "clamped to ids.len()");
        assert_eq!(vm.confirm_all(), 1);
    }
}
