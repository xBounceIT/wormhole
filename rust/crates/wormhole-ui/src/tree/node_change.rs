//! Live-refresh glue: `wormhole-domain` [`ConnectionNodeChangeNotifier`](wormhole_domain::ConnectionNodeChangeNotifier)
//! events → tree / open-session refresh requests (pure Rust; no GPUI / no I/O).
//!
//! C# parity: `ViewModels/ConnectionTreeViewModel.cs` subscribes to
//! `IConnectionNodeChangeNotifier.ConnectionNodeUpdated` and reacts by either
//! reloading the whole tree (`RefreshAsync` after structural edits) or patching
//! one row in place (`ApplyConnectionNodeUpdated`, a no-op for ids the snapshot
//! does not know). Session hosts additionally re-resolve inherited profiles when
//! a row changes. C# today publishes **updated** only; the Rust domain extends the
//! publish surface to **create / delete / reparent** (see
//! `wormhole-domain` `connection_node_change`). This glue translates every event
//! into sink requests and never loads data itself — the host's [`TreeRefreshSink`]
//! decides how to refresh (patch in place, reload, or ignore an unknown id).
//!
//! | [`ConnectionNodeChangeEvent`] | Sink requests (in order) |
//! |---|---|
//! | Created (any kind) | `FullReload` |
//! | Updated (connection) | `InPlacePatch { id }`, `ProfileRefresh { id }` |
//! | Updated (folder) | `InPlacePatch { id }`, `ProfileRefresh { id }`, `SessionRefresh { id }` |
//! | Deleted (connection) | `FullReload`, `ProfileRefresh { id }` |
//! | Deleted (folder) | `FullReload`, `ProfileRefresh { id }`, `SessionRefresh { id }` |
//! | Reparented (any kind) | `FullReload`, `ProfileRefresh { id }` (+ `SessionRefresh { id }` when the row is a folder) |
//!
//! Fail-closed table:
//!
//! | Condition | Result |
//! |---|---|
//! | Event referencing an unknown node id (row already deleted) | **no panic**; reload / refresh hints still recorded — the sink decides (mirrors C# `ApplyConnectionNodeUpdated` no-op for unknown ids) |
//! | Poisoned [`Mutex`] (glue state or fake sink) | poison recovered (`into_inner`); treated as no-op |
//! | Stale callback invoked after unsubscribe (in-flight fan-out or misbehaving notifier) | dropped; counted in `suppressed_after_unsubscribe` |
//! | Stale callback from a registration superseded by re-subscribe | dropped; same `suppressed_after_unsubscribe` counter (epoch mismatch) |
//! | Duplicate / nested publishes | applied in **record order**, never deduped (a later delete is never lost behind an earlier update) |
//! | Notifier with no live subscriber wiring ([`NopConnectionNodeChangeNotifier`](wormhole_domain::NopConnectionNodeChangeNotifier)) | subscribe returns its sentinel handle; glue stays consistent, delivery is a no-op |
//!
//! Threading: notifier callbacks run on arbitrary threads (`Send + Sync`). The glue
//! is `Send + Sync`; sinks are invoked synchronously on the notifier's thread, so
//! hosts must marshal to the UI thread themselves (e.g. `DispatcherQueue.TryEnqueue`).
//! The glue does not require — or use — a dispatcher.
//!
//! **Never** log or attach secrets: events are metadata-only (ids + [`NodeKind`] +
//! parent pointers) and [`Debug`] prints counters and the subscription handle only.

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use uuid::Uuid;

use wormhole_domain::{
    ConnectionNodeChangeCallback, ConnectionNodeChangeEvent, ConnectionNodeChangeSubscription,
    SharedConnectionNodeChangeNotifier,
};

/// One recorded refresh request emitted by [`TreeNodeChangeGlue`] to a
/// [`TreeRefreshSink`] for a single [`ConnectionNodeChangeEvent`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TreeRefreshCall {
    /// The whole tree must be reloaded (created / deleted / reparented).
    FullReload,
    /// One row can be patched in place; the sink decides whether to patch or reload.
    InPlacePatch { node_id: Uuid },
    /// Open sessions referencing `node_id` should re-resolve their profile.
    ProfileRefresh { node_id: Uuid },
    /// Open sessions under a changed folder subtree may be affected by inheritance.
    SessionRefresh { node_id: Uuid },
}

/// Sink receiving tree / open-session refresh requests from [`TreeNodeChangeGlue`].
///
/// Methods are invoked synchronously on the notifier's thread — an arbitrary worker
/// thread, never assumed to be the UI thread. Implementations must be `Send + Sync`
/// and tolerate cross-thread calls; hosts marshal to the UI thread themselves
/// (e.g. `DispatcherQueue.TryEnqueue`). The glue does not require a dispatcher.
pub trait TreeRefreshSink: Send + Sync {
    /// Full reload (structural change).
    fn request_full_reload(&self);
    /// In-place patch candidate for one row; the sink may fall back to reloading
    /// when it does not know the id (C# `ApplyConnectionNodeUpdated` semantics).
    fn request_in_place_patch(&self, node_id: Uuid);
    /// Open sessions should re-resolve their (possibly inherited) profile.
    fn request_profile_refresh(&self, node_id: Uuid);
    /// Open sessions under a changed folder subtree should re-resolve.
    fn request_session_refresh(&self, node_id: Uuid);
}

/// Snapshot of [`TreeNodeChangeGlue`] delivery counters (metadata only; never
/// node payloads beyond the ids hosts already saw in their events).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TreeNodeChangeCounters {
    /// Events delivered to the sink pipeline (after the active-subscription check).
    pub events_seen: u64,
    pub full_reloads: u64,
    pub in_place_patches: u64,
    pub profile_refreshes: u64,
    pub session_refreshes: u64,
    /// Stale-callback invocations dropped because the subscription was cancelled.
    pub suppressed_after_unsubscribe: u64,
}

/// Subscribes a [`TreeRefreshSink`] to a [`ConnectionNodeChangeNotifier`] and
/// translates each [`ConnectionNodeChangeEvent`] into refresh requests.
///
/// Lifecycle: [`subscribe`](Self::subscribe) (idempotent, returns the opaque
/// [`ConnectionNodeChangeSubscription`]), [`unsubscribe`](Self::unsubscribe) /
/// [`close`](Self::close) (idempotent; double-unsubscribe is a no-op), and [`Drop`]
/// unsubscribes a still-live subscription. Unsubscribing stops future delivery;
/// a callback already past the liveness check when a fan-out is in flight may
/// deliver one last event; anything invoked afterwards is suppressed and counted.
///
/// The glue is thread-safe: `&self` methods and the callback share an [`Arc`]
/// `Mutex` state plus atomic counters. It never loads data and never records
/// node payloads.
pub struct TreeNodeChangeGlue {
    notifier: SharedConnectionNodeChangeNotifier,
    sink: Arc<dyn TreeRefreshSink>,
    state: Arc<Mutex<GlueState>>,
    counters: Arc<AtomicCounters>,
}

#[derive(Debug, Default)]
struct GlueState {
    subscription: Option<ConnectionNodeChangeSubscription>,
    /// Monotonic registration generation. Bumped on every successful subscribe
    /// so a callback from a **previous** registration stays suppressed even if
    /// the host unsubscribes and re-subscribes while an old fan-out is in flight.
    epoch: u64,
}

#[derive(Default)]
struct AtomicCounters {
    events_seen: AtomicU64,
    full_reloads: AtomicU64,
    in_place_patches: AtomicU64,
    profile_refreshes: AtomicU64,
    session_refreshes: AtomicU64,
    suppressed_after_unsubscribe: AtomicU64,
}

impl AtomicCounters {
    fn snapshot(&self) -> TreeNodeChangeCounters {
        TreeNodeChangeCounters {
            events_seen: self.events_seen.load(Ordering::Relaxed),
            full_reloads: self.full_reloads.load(Ordering::Relaxed),
            in_place_patches: self.in_place_patches.load(Ordering::Relaxed),
            profile_refreshes: self.profile_refreshes.load(Ordering::Relaxed),
            session_refreshes: self.session_refreshes.load(Ordering::Relaxed),
            suppressed_after_unsubscribe: self.suppressed_after_unsubscribe.load(Ordering::Relaxed),
        }
    }
}

impl TreeNodeChangeGlue {
    /// Create glue around `notifier` and a shared, possibly cloned sink.
    pub fn new(notifier: SharedConnectionNodeChangeNotifier, sink: Arc<dyn TreeRefreshSink>) -> Self {
        Self {
            notifier,
            sink,
            state: Arc::new(Mutex::new(GlueState::default())),
            counters: Arc::new(AtomicCounters::default()),
        }
    }

    /// Create glue around `notifier` and a concrete [`TreeRefreshSink`] value.
    pub fn with_sink<S>(notifier: SharedConnectionNodeChangeNotifier, sink: S) -> Self
    where
        S: TreeRefreshSink + 'static,
    {
        Self::new(notifier, Arc::new(sink))
    }

    /// Subscribe the internal callback to the notifier (idempotent).
    ///
    /// Returns the opaque [`ConnectionNodeChangeSubscription`] the notifier minted.
    /// A second call while already subscribed returns the existing handle without
    /// registering a second callback (so `Drop` never leaks a subscription).
    ///
    /// The glue's state lock is held across `notifier.subscribe`, so a concurrent
    /// `subscribe` cannot double-register and a concurrent `publish` cannot
    /// deliver into the window between registration and the state store (no lost
    /// or duplicated events). The notifier must not invoke the listener from
    /// inside `subscribe` (out of contract — it would deadlock on the held lock).
    pub fn subscribe(&self) -> ConnectionNodeChangeSubscription {
        let mut state = lock(&self.state);
        if let Some(existing) = state.subscription {
            return existing;
        }
        state.epoch = state.epoch.wrapping_add(1);
        let fresh = self.notifier.subscribe(self.callback(state.epoch));
        state.subscription = Some(fresh);
        fresh
    }

    /// Remove the subscription from the notifier. Returns `true` when the glue had
    /// a live subscription; a double unsubscribe is a no-op returning `false`.
    pub fn unsubscribe(&self) -> bool {
        let subscription = {
            let mut state = lock(&self.state);
            state.subscription.take()
        };
        let Some(id) = subscription else {
            return false;
        };
        self.notifier.unsubscribe(id);
        true
    }

    /// Idempotent close: same as [`unsubscribe`](Self::unsubscribe), unit-returning.
    pub fn close(&self) {
        let _ = self.unsubscribe();
    }

    /// The live subscription handle, if any.
    pub fn current_subscription(&self) -> Option<ConnectionNodeChangeSubscription> {
        lock(&self.state).subscription
    }

    /// Whether a subscription is currently live.
    pub fn is_subscribed(&self) -> bool {
        self.current_subscription().is_some()
    }

    /// Snapshot of delivery counters.
    pub fn counters(&self) -> TreeNodeChangeCounters {
        self.counters.snapshot()
    }

    fn callback(&self, epoch: u64) -> ConnectionNodeChangeCallback {
        let state = Arc::clone(&self.state);
        let sink = Arc::clone(&self.sink);
        let counters = Arc::clone(&self.counters);
        Arc::new(move |event: &ConnectionNodeChangeEvent| {
            // Fail-closed: a stale callback (subscription cancelled while a fan-out
            // was in flight, a misbehaving notifier that keeps invoking us after
            // unsubscribe, or an old registration superseded by a re-subscribe)
            // is a counted no-op, never a panic or a sink call.
            let active = {
                let state = lock(&state);
                state.subscription.is_some() && state.epoch == epoch
            };
            if !active {
                counters
                    .suppressed_after_unsubscribe
                    .fetch_add(1, Ordering::Relaxed);
                return;
            }
            counters.events_seen.fetch_add(1, Ordering::Relaxed);
            translate(event, sink.as_ref(), &counters);
        })
    }
}

impl Drop for TreeNodeChangeGlue {
    fn drop(&mut self) {
        let _ = self.unsubscribe();
    }
}

impl fmt::Debug for TreeNodeChangeGlue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TreeNodeChangeGlue")
            .field("subscription", &self.current_subscription())
            .field("counters", &self.counters())
            .finish()
    }
}

fn translate(
    event: &ConnectionNodeChangeEvent,
    sink: &dyn TreeRefreshSink,
    counters: &AtomicCounters,
) {
    if event.suggests_tree_reload() {
        counters.full_reloads.fetch_add(1, Ordering::Relaxed);
        sink.request_full_reload();
    } else {
        counters.in_place_patches.fetch_add(1, Ordering::Relaxed);
        sink.request_in_place_patch(event.node_id);
    }

    if event.suggests_session_profile_refresh() {
        counters.profile_refreshes.fetch_add(1, Ordering::Relaxed);
        sink.request_profile_refresh(event.node_id);
    }

    if event.may_affect_descendant_sessions() {
        counters.session_refreshes.fetch_add(1, Ordering::Relaxed);
        sink.request_session_refresh(event.node_id);
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Recording [`TreeRefreshSink`] for tests / Lab demos (thread-safe, cloneable).
/// [`Debug`] prints the recorded-call **count** only — node ids never leave the
/// recorded calls through a `Debug` rendering.
#[derive(Clone, Default)]
pub struct FakeTreeRefreshSink {
    calls: Arc<Mutex<Vec<TreeRefreshCall>>>,
}

impl FakeTreeRefreshSink {
    pub fn new() -> Self {
        Self::default()
    }

    /// All recorded calls, in delivery order.
    pub fn calls(&self) -> Vec<TreeRefreshCall> {
        lock(&self.calls).clone()
    }

    pub fn clear(&self) {
        lock(&self.calls).clear();
    }

    pub fn len(&self) -> usize {
        lock(&self.calls).len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn full_reload_count(&self) -> usize {
        self.count(|c| matches!(c, TreeRefreshCall::FullReload))
    }

    pub fn in_place_patch_count(&self) -> usize {
        self.count(|c| matches!(c, TreeRefreshCall::InPlacePatch { .. }))
    }

    pub fn profile_refresh_count(&self) -> usize {
        self.count(|c| matches!(c, TreeRefreshCall::ProfileRefresh { .. }))
    }

    pub fn session_refresh_count(&self) -> usize {
        self.count(|c| matches!(c, TreeRefreshCall::SessionRefresh { .. }))
    }

    fn count(&self, predicate: impl Fn(&TreeRefreshCall) -> bool) -> usize {
        lock(&self.calls).iter().filter(|c| predicate(c)).count()
    }
}

impl fmt::Debug for FakeTreeRefreshSink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FakeTreeRefreshSink")
            .field("recorded_calls", &self.len())
            .finish()
    }
}

impl TreeRefreshSink for FakeTreeRefreshSink {
    fn request_full_reload(&self) {
        lock(&self.calls).push(TreeRefreshCall::FullReload);
    }

    fn request_in_place_patch(&self, node_id: Uuid) {
        lock(&self.calls).push(TreeRefreshCall::InPlacePatch { node_id });
    }

    fn request_profile_refresh(&self, node_id: Uuid) {
        lock(&self.calls).push(TreeRefreshCall::ProfileRefresh { node_id });
    }

    fn request_session_refresh(&self, node_id: Uuid) {
        lock(&self.calls).push(TreeRefreshCall::SessionRefresh { node_id });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;
    use std::sync::{Arc, Barrier, Weak};
    use std::thread;
    use std::time::Duration;
    use wormhole_domain::{
        ConnectionNodeChangeKind, ConnectionNodeChangeNotifier, ConnectionNodeChangePublisher,
        FakeConnectionNodeChangeNotifier, NopConnectionNodeChangeNotifier, NodeKind,
    };

    fn new_notifier() -> Arc<FakeConnectionNodeChangeNotifier> {
        Arc::new(FakeConnectionNodeChangeNotifier::new())
    }

    fn new_glue(notifier: &Arc<FakeConnectionNodeChangeNotifier>) -> (FakeTreeRefreshSink, TreeNodeChangeGlue) {
        let sink = FakeTreeRefreshSink::new();
        let glue = TreeNodeChangeGlue::new(notifier.clone(), Arc::new(sink.clone()));
        (sink, glue)
    }

    #[test]
    fn created_event_requests_full_reload() {
        let notifier = new_notifier();
        let (sink, glue) = new_glue(&notifier);
        glue.subscribe();

        notifier.publish_created(Uuid::new_v4(), NodeKind::Connection, None);

        assert_eq!(sink.calls(), vec![TreeRefreshCall::FullReload]);
        assert_eq!(glue.counters().events_seen, 1);
        assert_eq!(glue.counters().full_reloads, 1);
        assert_eq!(glue.counters().in_place_patches, 0);
    }

    #[test]
    fn created_folder_does_not_emit_profile_or_session_hints() {
        let notifier = new_notifier();
        let sink = FakeTreeRefreshSink::new();
        let glue = TreeNodeChangeGlue::with_sink(notifier.clone(), sink.clone());
        glue.subscribe();

        notifier.publish_created(Uuid::new_v4(), NodeKind::Folder, None);

        assert_eq!(sink.calls(), vec![TreeRefreshCall::FullReload]);
        assert_eq!(sink.profile_refresh_count(), 0);
        assert_eq!(sink.session_refresh_count(), 0);
        assert_eq!(glue.counters().profile_refreshes, 0);
    }

    #[test]
    fn updated_connection_requests_in_place_patch() {
        let notifier = new_notifier();
        let (sink, glue) = new_glue(&notifier);
        glue.subscribe();
        let id = Uuid::new_v4();

        notifier.publish_updated(id, NodeKind::Connection, None);

        assert_eq!(
            sink.calls(),
            vec![
                TreeRefreshCall::InPlacePatch { node_id: id },
                TreeRefreshCall::ProfileRefresh { node_id: id },
            ]
        );
        assert_eq!(sink.full_reload_count(), 0);
        assert_eq!(sink.session_refresh_count(), 0);
        assert_eq!(glue.counters().in_place_patches, 1);
        assert_eq!(glue.counters().profile_refreshes, 1);
    }

    #[test]
    fn deleted_event_requests_full_reload() {
        let notifier = new_notifier();
        let (sink, glue) = new_glue(&notifier);
        glue.subscribe();
        let id = Uuid::new_v4();
        let parent = Uuid::new_v4();

        notifier.publish_deleted(id, NodeKind::Connection, Some(parent));

        assert_eq!(
            sink.calls(),
            vec![
                TreeRefreshCall::FullReload,
                TreeRefreshCall::ProfileRefresh { node_id: id },
            ]
        );
        assert_eq!(glue.counters().full_reloads, 1);
    }

    #[test]
    fn deleted_folder_requests_reload_plus_descendant_hint() {
        let notifier = new_notifier();
        let (sink, glue) = new_glue(&notifier);
        glue.subscribe();
        let folder = Uuid::new_v4();

        notifier.publish_deleted(folder, NodeKind::Folder, None);

        assert_eq!(
            sink.calls(),
            vec![
                TreeRefreshCall::FullReload,
                TreeRefreshCall::ProfileRefresh { node_id: folder },
                TreeRefreshCall::SessionRefresh { node_id: folder },
            ]
        );
        assert_eq!(glue.counters().full_reloads, 1);
        assert_eq!(glue.counters().session_refreshes, 1);
    }

    #[test]
    fn reparented_connection_requests_reload_without_descendant_hint() {
        let notifier = new_notifier();
        let (sink, glue) = new_glue(&notifier);
        glue.subscribe();
        let conn = Uuid::new_v4();

        notifier.publish_reparented(conn, NodeKind::Connection, Some(Uuid::new_v4()), None);

        assert_eq!(
            sink.calls(),
            vec![
                TreeRefreshCall::FullReload,
                TreeRefreshCall::ProfileRefresh { node_id: conn },
            ]
        );
        assert_eq!(sink.session_refresh_count(), 0);
        assert_eq!(glue.counters().full_reloads, 1);
    }

    #[test]
    fn reparented_folder_requests_reload_plus_descendant_hint() {
        let notifier = new_notifier();
        let (sink, glue) = new_glue(&notifier);
        glue.subscribe();
        let folder = Uuid::new_v4();
        let old_parent = Uuid::new_v4();
        let new_parent = Uuid::new_v4();

        notifier.publish_reparented(folder, NodeKind::Folder, Some(old_parent), Some(new_parent));

        assert_eq!(
            sink.calls(),
            vec![
                TreeRefreshCall::FullReload,
                TreeRefreshCall::ProfileRefresh { node_id: folder },
                TreeRefreshCall::SessionRefresh { node_id: folder },
            ]
        );
        assert_eq!(glue.counters().full_reloads, 1);
        assert_eq!(glue.counters().session_refreshes, 1);
    }

    #[test]
    fn updated_folder_requests_profile_and_descendant_hints_without_reload() {
        let notifier = new_notifier();
        let (sink, glue) = new_glue(&notifier);
        glue.subscribe();
        let folder = Uuid::new_v4();

        notifier.publish_updated(folder, NodeKind::Folder, None);

        assert_eq!(
            sink.calls(),
            vec![
                TreeRefreshCall::InPlacePatch { node_id: folder },
                TreeRefreshCall::ProfileRefresh { node_id: folder },
                TreeRefreshCall::SessionRefresh { node_id: folder },
            ]
        );
        assert_eq!(sink.full_reload_count(), 0);
        assert_eq!(glue.counters().full_reloads, 0);
        assert_eq!(glue.counters().session_refreshes, 1);
    }

    #[test]
    fn unknown_id_delete_does_not_panic_and_records_reload() {
        let notifier = new_notifier();
        let (sink, glue) = new_glue(&notifier);
        glue.subscribe();
        let unknown = Uuid::new_v4();

        notifier.publish_deleted(unknown, NodeKind::Connection, None);

        assert_eq!(
            sink.calls(),
            vec![
                TreeRefreshCall::FullReload,
                TreeRefreshCall::ProfileRefresh { node_id: unknown },
            ]
        );
        assert_eq!(glue.counters().events_seen, 1);
    }

    #[test]
    fn subscribe_returns_opaque_subscription_and_is_idempotent() {
        let notifier = new_notifier();
        let (_, glue) = new_glue(&notifier);
        assert!(!glue.is_subscribed());

        let first = glue.subscribe();
        assert!(first.as_u64() > 0);
        assert!(glue.is_subscribed());
        assert_eq!(glue.current_subscription(), Some(first));
        assert_eq!(notifier.subscriber_count(), 1);

        let second = glue.subscribe();
        assert_eq!(first, second);
        assert_eq!(notifier.subscriber_count(), 1);
    }

    #[test]
    fn unsubscribe_stops_delivery() {
        let notifier = new_notifier();
        let (sink, glue) = new_glue(&notifier);
        glue.subscribe();
        let id = Uuid::new_v4();

        notifier.publish_updated(id, NodeKind::Connection, None);
        assert_eq!(sink.len(), 2);

        assert!(glue.unsubscribe());
        assert_eq!(notifier.subscriber_count(), 0);

        notifier.publish_updated(id, NodeKind::Connection, None);
        assert_eq!(sink.len(), 2);
        assert_eq!(glue.counters().events_seen, 1);
    }

    #[test]
    fn double_unsubscribe_is_noop() {
        let notifier = new_notifier();
        let (sink, glue) = new_glue(&notifier);
        assert!(!glue.unsubscribe());

        glue.subscribe();
        assert!(glue.unsubscribe());
        assert!(!glue.unsubscribe());
        assert!(!glue.is_subscribed());
        assert_eq!(notifier.subscriber_count(), 0);

        notifier.publish_created(Uuid::new_v4(), NodeKind::Connection, None);
        assert!(sink.is_empty());
    }

    #[test]
    fn drop_and_close_are_idempotent() {
        let notifier = new_notifier();
        let sink = FakeTreeRefreshSink::new();

        {
            let glue = TreeNodeChangeGlue::new(notifier.clone(), Arc::new(sink.clone()));
            glue.subscribe();
            assert_eq!(notifier.subscriber_count(), 1);
            glue.close();
            glue.close();
            assert!(!glue.is_subscribed());
            assert_eq!(notifier.subscriber_count(), 0);
        }

        {
            let glue = TreeNodeChangeGlue::new(notifier.clone(), Arc::new(sink.clone()));
            glue.subscribe();
            assert_eq!(notifier.subscriber_count(), 1);
        }
        assert_eq!(notifier.subscriber_count(), 0);

        notifier.publish_created(Uuid::new_v4(), NodeKind::Connection, None);
        assert!(sink.is_empty());
    }

    #[test]
    fn nested_publish_preserves_record_order() {
        let notifier = new_notifier();
        let (sink, glue) = new_glue(&notifier);
        glue.subscribe();
        let id = Uuid::new_v4();

        // Second listener re-publishes an Updated from inside the Created fan-out
        // (nested publish); the glue must still see Created before Updated.
        let nested = Arc::clone(&notifier);
        notifier.subscribe(Arc::new(move |event: &ConnectionNodeChangeEvent| {
            if event.change == ConnectionNodeChangeKind::Created {
                nested.publish_updated(id, NodeKind::Connection, None);
            }
        }));

        notifier.publish_created(id, NodeKind::Connection, None);

        assert_eq!(
            sink.calls(),
            vec![
                TreeRefreshCall::FullReload,
                TreeRefreshCall::InPlacePatch { node_id: id },
                TreeRefreshCall::ProfileRefresh { node_id: id },
            ]
        );
        assert_eq!(glue.counters().events_seen, 2);
    }

    #[test]
    fn duplicate_events_applied_in_order_without_dedupe() {
        let notifier = new_notifier();
        let (sink, glue) = new_glue(&notifier);
        glue.subscribe();
        let id = Uuid::new_v4();

        notifier.publish_updated(id, NodeKind::Connection, None);
        notifier.publish_deleted(id, NodeKind::Connection, None);

        assert_eq!(
            sink.calls(),
            vec![
                TreeRefreshCall::InPlacePatch { node_id: id },
                TreeRefreshCall::ProfileRefresh { node_id: id },
                TreeRefreshCall::FullReload,
                TreeRefreshCall::ProfileRefresh { node_id: id },
            ]
        );
        assert_eq!(glue.counters().in_place_patches, 1);
        assert_eq!(glue.counters().full_reloads, 1);
    }

    #[test]
    fn debug_redaction_omits_node_ids() {
        let notifier = new_notifier();
        let (sink, glue) = new_glue(&notifier);
        glue.subscribe();
        let node_id = Uuid::new_v4();

        notifier.publish_updated(node_id, NodeKind::Connection, None);
        notifier.publish_deleted(node_id, NodeKind::Connection, None);
        assert_eq!(sink.len(), 4);

        let rendered = format!("{glue:?}");
        assert!(rendered.contains("subscription"));
        assert!(rendered.contains("counters"));
        assert!(rendered.contains("events_seen"));
        assert!(!rendered.contains(&node_id.to_string()));
        // The recording sink's Debug renders the call count only, never ids.
        let rendered_sink = format!("{sink:?}");
        assert!(rendered_sink.contains("recorded_calls"));
        assert!(!rendered_sink.contains(&node_id.to_string()));
    }

    #[test]
    fn thread_safety_concurrent_publishers() {
        let notifier = new_notifier();
        let (sink, glue) = new_glue(&notifier);
        glue.subscribe();
        const THREADS: usize = 4;
        const PER_THREAD: usize = 25;

        let handles: Vec<_> = (0..THREADS)
            .map(|_| {
                let notifier = Arc::clone(&notifier);
                thread::spawn(move || {
                    for _ in 0..PER_THREAD {
                        notifier.publish_updated(Uuid::new_v4(), NodeKind::Connection, None);
                    }
                })
            })
            .collect();
        for handle in handles {
            handle.join().unwrap();
        }

        let expected = (THREADS * PER_THREAD) as u64;
        assert_eq!(glue.counters().events_seen, expected);
        assert_eq!(glue.counters().in_place_patches, expected);
        assert_eq!(glue.counters().profile_refreshes, expected);
        assert_eq!(glue.counters().session_refreshes, 0);
        assert_eq!(glue.counters().suppressed_after_unsubscribe, 0);
        assert_eq!(sink.in_place_patch_count(), expected as usize);
        assert_eq!(sink.profile_refresh_count(), expected as usize);
        assert_eq!(sink.full_reload_count(), 0);
    }

    #[test]
    fn concurrent_subscribe_and_publish_never_loses_or_duplicates() {
        let notifier = new_notifier();
        let (sink, glue) = new_glue(&notifier);
        let glue = Arc::new(glue);
        const PUBLISHERS: usize = 2;
        const SUBSCRIBERS: usize = 4;
        const EVENTS: usize = 150;

        let publishers: Vec<_> = (0..PUBLISHERS)
            .map(|_| {
                let notifier = Arc::clone(&notifier);
                thread::spawn(move || {
                    for _ in 0..EVENTS {
                        notifier.publish_updated(Uuid::new_v4(), NodeKind::Connection, None);
                    }
                })
            })
            .collect();
        let subscribers: Vec<_> = (0..SUBSCRIBERS)
            .map(|_| {
                let glue = Arc::clone(&glue);
                thread::spawn(move || {
                    for _ in 0..50 {
                        let _ = glue.subscribe();
                    }
                })
            })
            .collect();
        for handle in publishers.into_iter().chain(subscribers) {
            handle.join().unwrap();
        }

        // Exactly one live registration survived the subscribe race.
        assert_eq!(notifier.subscriber_count(), 1);
        // Every delivered event was translated exactly once and consistently.
        assert_eq!(glue.counters().events_seen, glue.counters().in_place_patches);
        assert_eq!(glue.counters().events_seen, glue.counters().profile_refreshes);
        assert_eq!(sink.in_place_patch_count(), glue.counters().events_seen as usize);
        assert_eq!(sink.profile_refresh_count(), glue.counters().events_seen as usize);

        // Once quiescent, a single publish is delivered exactly once.
        let before = glue.counters().events_seen;
        let before_calls = sink.len();
        notifier.publish_updated(Uuid::new_v4(), NodeKind::Connection, None);
        assert_eq!(glue.counters().events_seen, before + 1);
        assert_eq!(sink.len(), before_calls + 2);
    }

    #[test]
    fn unsubscribe_racing_publishers_keeps_delivery_consistent() {
        let notifier = new_notifier();
        let (sink, glue) = new_glue(&notifier);
        glue.subscribe();
        let barrier = Arc::new(Barrier::new(3));

        let publishers: Vec<_> = (0..2)
            .map(|_| {
                let notifier = Arc::clone(&notifier);
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    for _ in 0..300 {
                        notifier.publish_updated(Uuid::new_v4(), NodeKind::Connection, None);
                    }
                })
            })
            .collect();
        barrier.wait();
        assert!(glue.unsubscribe());
        for handle in publishers {
            handle.join().unwrap();
        }

        assert_eq!(notifier.subscriber_count(), 0);
        assert_eq!(sink.in_place_patch_count(), sink.profile_refresh_count());
        assert_eq!(glue.counters().events_seen, glue.counters().in_place_patches);
        assert_eq!(glue.counters().events_seen, glue.counters().profile_refreshes);
        let delivered = glue.counters().events_seen;
        let suppressed = glue.counters().suppressed_after_unsubscribe;

        // Post-unsubscribe publishes are never delivered or counted.
        notifier.publish_updated(Uuid::new_v4(), NodeKind::Connection, None);
        assert_eq!(glue.counters().events_seen, delivered);
        assert_eq!(glue.counters().suppressed_after_unsubscribe, suppressed);
        assert_eq!(sink.len(), delivered as usize * 2);
    }

    #[test]
    fn dropping_glue_while_publishing_is_safe() {
        let notifier = new_notifier();
        let sink = FakeTreeRefreshSink::new();
        {
            let glue = TreeNodeChangeGlue::new(notifier.clone(), Arc::new(sink.clone()));
            glue.subscribe();
            let handle = thread::spawn({
                let notifier = Arc::clone(&notifier);
                move || {
                    for _ in 0..1000 {
                        notifier.publish_updated(Uuid::new_v4(), NodeKind::Connection, None);
                    }
                }
            });
            thread::sleep(Duration::from_millis(5));
            drop(glue);
            handle.join().unwrap();
        }
        assert_eq!(notifier.subscriber_count(), 0);
        assert_eq!(sink.in_place_patch_count(), sink.profile_refresh_count());
    }

    /// Sink that unsubscribes the glue from inside its own sink call (host
    /// tearing itself down re-entrantly — must not deadlock).
    struct UnsubscribingSink {
        inner: FakeTreeRefreshSink,
        glue: Mutex<Option<Weak<TreeNodeChangeGlue>>>,
        unsubscribed: AtomicBool,
    }

    impl TreeRefreshSink for UnsubscribingSink {
        fn request_full_reload(&self) {
            self.inner.request_full_reload();
            if !self.unsubscribed.swap(true, Ordering::Relaxed) {
                if let Some(glue) = lock(&self.glue).clone().and_then(|w| w.upgrade()) {
                    glue.unsubscribe();
                }
            }
        }

        fn request_in_place_patch(&self, node_id: Uuid) {
            self.inner.request_in_place_patch(node_id);
        }

        fn request_profile_refresh(&self, node_id: Uuid) {
            self.inner.request_profile_refresh(node_id);
        }

        fn request_session_refresh(&self, node_id: Uuid) {
            self.inner.request_session_refresh(node_id);
        }
    }

    #[test]
    fn unsubscribing_from_inside_sink_does_not_deadlock() {
        let notifier = new_notifier();
        let sink = FakeTreeRefreshSink::new();
        let unsubscribing = Arc::new(UnsubscribingSink {
            inner: sink.clone(),
            glue: Mutex::new(None),
            unsubscribed: AtomicBool::new(false),
        });
        let glue = Arc::new(TreeNodeChangeGlue::new(
            notifier.clone(),
            Arc::clone(&unsubscribing) as Arc<dyn TreeRefreshSink>,
        ));
        *lock(&unsubscribing.glue) = Some(Arc::downgrade(&glue));
        glue.subscribe();
        let id = Uuid::new_v4();

        notifier.publish_created(id, NodeKind::Connection, None);
        assert_eq!(sink.calls(), vec![TreeRefreshCall::FullReload]);
        assert_eq!(notifier.subscriber_count(), 0);
        assert_eq!(glue.counters().events_seen, 1);

        notifier.publish_created(id, NodeKind::Connection, None);
        assert_eq!(sink.calls(), vec![TreeRefreshCall::FullReload]);
        assert_eq!(glue.counters().events_seen, 1);
    }

    /// Sink that re-publishes an Updated event from inside `request_full_reload`
    /// (worst-case re-entrant publish from the glue's own delivery path).
    struct ReentrantSink {
        inner: FakeTreeRefreshSink,
        notifier: SharedConnectionNodeChangeNotifier,
        node_id: Uuid,
    }

    impl TreeRefreshSink for ReentrantSink {
        fn request_full_reload(&self) {
            self.inner.request_full_reload();
            self.notifier
                .publish_updated(self.node_id, NodeKind::Connection, None);
        }

        fn request_in_place_patch(&self, node_id: Uuid) {
            self.inner.request_in_place_patch(node_id);
        }

        fn request_profile_refresh(&self, node_id: Uuid) {
            self.inner.request_profile_refresh(node_id);
        }

        fn request_session_refresh(&self, node_id: Uuid) {
            self.inner.request_session_refresh(node_id);
        }
    }

    #[test]
    fn sink_republish_from_full_reload_preserves_order_without_deadlock() {
        let notifier = new_notifier();
        let sink = FakeTreeRefreshSink::new();
        let id = Uuid::new_v4();
        let reentrant = ReentrantSink {
            inner: sink.clone(),
            notifier: notifier.clone(),
            node_id: id,
        };
        let glue = TreeNodeChangeGlue::with_sink(notifier.clone(), reentrant);
        glue.subscribe();

        notifier.publish_created(id, NodeKind::Connection, None);

        assert_eq!(
            sink.calls(),
            vec![
                TreeRefreshCall::FullReload,
                TreeRefreshCall::InPlacePatch { node_id: id },
                TreeRefreshCall::ProfileRefresh { node_id: id },
            ]
        );
        assert_eq!(glue.counters().events_seen, 2);
        assert_eq!(glue.counters().full_reloads, 1);
    }

    #[test]
    fn nop_notifier_subscription_is_sentinel_and_lifecycle_is_noop() {
        let notifier: SharedConnectionNodeChangeNotifier =
            Arc::new(NopConnectionNodeChangeNotifier);
        let sink = FakeTreeRefreshSink::new();
        let glue = TreeNodeChangeGlue::with_sink(notifier, sink.clone());
        assert!(!glue.is_subscribed());

        let sub = glue.subscribe();
        assert_eq!(sub.as_u64(), 0);
        assert!(glue.is_subscribed());
        assert_eq!(glue.current_subscription(), Some(sub));

        assert!(glue.unsubscribe());
        assert!(!glue.unsubscribe());
        assert!(!glue.is_subscribed());
        assert!(sink.is_empty());
        assert_eq!(glue.counters(), TreeNodeChangeCounters::default());
    }

    /// Notifier whose first `subscribe` panics, poisoning the glue's state mutex.
    struct PanicOnSubscribeNotifier {
        callback: Mutex<Option<ConnectionNodeChangeCallback>>,
        panicked: AtomicBool,
        last: Mutex<Option<ConnectionNodeChangeSubscription>>,
    }

    impl PanicOnSubscribeNotifier {
        fn new() -> Self {
            let subscription = FakeConnectionNodeChangeNotifier::new()
                .subscribe(Arc::new(|_: &ConnectionNodeChangeEvent| {}));
            Self {
                callback: Mutex::new(None),
                panicked: AtomicBool::new(false),
                last: Mutex::new(Some(subscription)),
            }
        }
    }

    impl ConnectionNodeChangeNotifier for PanicOnSubscribeNotifier {
        fn publish(&self, event: ConnectionNodeChangeEvent) {
            if let Some(callback) = lock(&self.callback).clone() {
                callback(&event);
            }
        }

        fn subscribe(
            &self,
            listener: ConnectionNodeChangeCallback,
        ) -> ConnectionNodeChangeSubscription {
            if !self.panicked.swap(true, Ordering::Relaxed) {
                panic!("hostile subscribe panic");
            }
            *lock(&self.callback) = Some(listener);
            lock(&self.last).clone().expect("seeded subscription")
        }

        fn unsubscribe(&self, _id: ConnectionNodeChangeSubscription) -> bool {
            true
        }
    }

    #[test]
    fn recovers_from_glue_state_poisoned_by_subscribe_panic() {
        let notifier: Arc<PanicOnSubscribeNotifier> = Arc::new(PanicOnSubscribeNotifier::new());
        let sink = FakeTreeRefreshSink::new();
        let glue = TreeNodeChangeGlue::new(notifier.clone(), Arc::new(sink.clone()));

        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            glue.subscribe();
        }));
        assert!(outcome.is_err());
        assert!(!glue.is_subscribed());

        // The poisoned mutex is recovered via `into_inner`; delivery still works.
        glue.subscribe();
        let id = Uuid::new_v4();
        notifier.publish_updated(id, NodeKind::Connection, None);
        assert_eq!(sink.len(), 2);
        assert_eq!(glue.counters().events_seen, 1);
        assert_eq!(glue.counters().suppressed_after_unsubscribe, 0);
        assert!(glue.unsubscribe());
    }

    /// Sink that panics on its very first call, poisoning its own recording mutex.
    struct PanickingSink {
        inner: FakeTreeRefreshSink,
        panicked: AtomicBool,
    }

    impl TreeRefreshSink for PanickingSink {
        fn request_full_reload(&self) {
            self.record(TreeRefreshCall::FullReload);
        }

        fn request_in_place_patch(&self, node_id: Uuid) {
            self.record(TreeRefreshCall::InPlacePatch { node_id });
        }

        fn request_profile_refresh(&self, node_id: Uuid) {
            self.record(TreeRefreshCall::ProfileRefresh { node_id });
        }

        fn request_session_refresh(&self, node_id: Uuid) {
            self.record(TreeRefreshCall::SessionRefresh { node_id });
        }
    }

    impl PanickingSink {
        fn record(&self, call: TreeRefreshCall) {
            if !self.panicked.swap(true, Ordering::Relaxed) {
                panic!("hostile sink panic");
            }
            lock(&self.inner.calls).push(call);
        }
    }

    #[test]
    fn recovers_from_sink_state_poisoned_by_sink_panic() {
        // The Fake notifier's fan-out loop has no panic-cleanup for a panicking
        // subscriber, so use the leaky single-callback notifier instead.
        let notifier: Arc<LeakyNotifier> = Arc::new(LeakyNotifier::new());
        let panicking = Arc::new(PanickingSink {
            inner: FakeTreeRefreshSink::new(),
            panicked: AtomicBool::new(false),
        });
        let sink = panicking.inner.clone();
        let glue = TreeNodeChangeGlue::new(notifier.clone(), panicking);
        glue.subscribe();
        let id = Uuid::new_v4();

        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            notifier.publish_updated(id, NodeKind::Connection, None);
        }));
        assert!(outcome.is_err());

        // The sink's poisoned mutex is recovered; the event is recorded normally.
        notifier.publish_updated(id, NodeKind::Connection, None);
        assert_eq!(glue.counters().events_seen, 2);
        assert_eq!(glue.counters().in_place_patches, 2);
        assert_eq!(
            sink.calls(),
            vec![
                TreeRefreshCall::InPlacePatch { node_id: id },
                TreeRefreshCall::ProfileRefresh { node_id: id },
            ]
        );
    }

    /// Notifier that never removes callbacks and invokes every registered callback
    /// forever (worst-case leaky fan-out across unsubscribe + re-subscribe).
    struct NeverForgetsNotifier {
        callbacks: Mutex<Vec<ConnectionNodeChangeCallback>>,
        handle: ConnectionNodeChangeSubscription,
    }

    impl NeverForgetsNotifier {
        fn new() -> Self {
            // Mint a valid opaque handle; this notifier never matches on ids anyway.
            let mint = FakeConnectionNodeChangeNotifier::new();
            let handle = mint.subscribe(Arc::new(|_: &ConnectionNodeChangeEvent| {}));
            Self {
                callbacks: Mutex::new(Vec::new()),
                handle,
            }
        }
    }

    impl ConnectionNodeChangeNotifier for NeverForgetsNotifier {
        fn publish(&self, event: ConnectionNodeChangeEvent) {
            for callback in lock(&self.callbacks).clone() {
                callback(&event);
            }
        }

        fn subscribe(
            &self,
            listener: ConnectionNodeChangeCallback,
        ) -> ConnectionNodeChangeSubscription {
            lock(&self.callbacks).push(listener);
            self.handle
        }

        fn unsubscribe(&self, _id: ConnectionNodeChangeSubscription) -> bool {
            true // Lies: the old callback keeps firing forever.
        }
    }

    #[test]
    fn superseded_registration_stale_callback_is_suppressed() {
        let notifier: Arc<NeverForgetsNotifier> = Arc::new(NeverForgetsNotifier::new());
        let sink = FakeTreeRefreshSink::new();
        let glue = TreeNodeChangeGlue::new(notifier.clone(), Arc::new(sink.clone()));
        glue.subscribe();
        let id = Uuid::new_v4();

        notifier.publish_updated(id, NodeKind::Connection, None);
        assert_eq!(sink.len(), 2);
        assert_eq!(glue.counters().events_seen, 1);

        // Unsubscribe + re-subscribe; the never-forgetting notifier still invokes
        // the OLD callback on every publish. Only the new registration may deliver.
        assert!(glue.unsubscribe());
        glue.subscribe();

        notifier.publish_updated(id, NodeKind::Connection, None);

        assert_eq!(sink.len(), 4);
        assert_eq!(glue.counters().events_seen, 2);
        assert_eq!(glue.counters().suppressed_after_unsubscribe, 1);
    }

    /// Notifier that keeps invoking the callback after `unsubscribe` (a "leak").
    /// The glue must treat the stale invocations as counted no-ops.
    struct LeakyNotifier {
        callback: Mutex<Option<ConnectionNodeChangeCallback>>,
        last: Mutex<Option<ConnectionNodeChangeSubscription>>,
    }

    impl LeakyNotifier {
        fn new() -> Self {
            // Mint a valid opaque subscription handle via the Fake notifier.
            let subscription = FakeConnectionNodeChangeNotifier::new()
                .subscribe(Arc::new(|_: &ConnectionNodeChangeEvent| {}));
            Self {
                callback: Mutex::new(None),
                last: Mutex::new(Some(subscription)),
            }
        }
    }

    impl ConnectionNodeChangeNotifier for LeakyNotifier {
        fn publish(&self, event: ConnectionNodeChangeEvent) {
            if let Some(callback) = lock(&self.callback).clone() {
                callback(&event);
            }
        }

        fn subscribe(
            &self,
            listener: ConnectionNodeChangeCallback,
        ) -> ConnectionNodeChangeSubscription {
            *lock(&self.callback) = Some(listener);
            lock(&self.last).clone().expect("seeded subscription")
        }

        fn unsubscribe(&self, _id: ConnectionNodeChangeSubscription) -> bool {
            true // Lies: the stale callback keeps firing.
        }
    }

    #[test]
    fn cancelled_subscription_from_misbehaving_notifier_is_noop() {
        let notifier: Arc<LeakyNotifier> = Arc::new(LeakyNotifier::new());
        let sink = FakeTreeRefreshSink::new();
        let glue = TreeNodeChangeGlue::new(notifier.clone(), Arc::new(sink.clone()));
        glue.subscribe();
        let id = Uuid::new_v4();

        notifier.publish_updated(id, NodeKind::Connection, None);
        assert_eq!(sink.len(), 2);
        assert_eq!(glue.counters().events_seen, 1);

        assert!(glue.unsubscribe());
        notifier.publish_updated(id, NodeKind::Connection, None);

        assert_eq!(sink.len(), 2);
        assert_eq!(glue.counters().events_seen, 1);
        assert_eq!(glue.counters().suppressed_after_unsubscribe, 1);
    }
}
