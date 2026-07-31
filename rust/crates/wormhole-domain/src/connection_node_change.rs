//! Connection / folder row change notifier glue (pure Rust; no GPUI / no I/O).
//!
//! Mirrors C# `IConnectionNodeChangeNotifier` / `ConnectionNodeChangeNotifier`
//! (`Services/IConnectionNodeChangeNotifier.cs`) and extends the publish surface
//! to **create / update / delete / reparent** so tree + open-session hosts can
//! refresh without secrets in the event payload.
//!
//! C# today publishes a full `ConnectionNode` clone on update only. This Fake
//! keeps events **metadata-only** (`node_id`, [`NodeKind`], parent ids, change
//! kind) — never passwords, private keys, tunnel payloads, or inline secrets.
//! Use [`ConnectionNodeChangeEvent::updated_from_node`] (and siblings) to strip
//! a domain row down to that shape.

use std::collections::VecDeque;
use std::fmt;
use std::sync::{Arc, Mutex};

use uuid::Uuid;

use crate::connection_node::ConnectionNode;
use crate::enums::NodeKind;

/// Kind of connection / folder row mutation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConnectionNodeChangeKind {
    Created,
    Updated,
    Deleted,
    Reparented,
}

impl fmt::Display for ConnectionNodeChangeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Created => "Created",
            Self::Updated => "Updated",
            Self::Deleted => "Deleted",
            Self::Reparented => "Reparented",
        })
    }
}

/// Metadata-only change event for tree / session refresh subscribers.
///
/// **Never** attach passwords, private keys, tunnel payloads, or other secret
/// material — only ids + [`NodeKind`] + parent pointers.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ConnectionNodeChangeEvent {
    pub node_id: Uuid,
    pub node_kind: NodeKind,
    pub change: ConnectionNodeChangeKind,
    /// Current / new parent folder id (`None` = root).
    pub parent_id: Option<Uuid>,
    /// Previous parent for [`ConnectionNodeChangeKind::Reparented`] only.
    pub previous_parent_id: Option<Uuid>,
}

impl ConnectionNodeChangeEvent {
    pub fn created(node_id: Uuid, node_kind: NodeKind, parent_id: Option<Uuid>) -> Self {
        Self {
            node_id,
            node_kind,
            change: ConnectionNodeChangeKind::Created,
            parent_id,
            previous_parent_id: None,
        }
    }

    pub fn updated(node_id: Uuid, node_kind: NodeKind, parent_id: Option<Uuid>) -> Self {
        Self {
            node_id,
            node_kind,
            change: ConnectionNodeChangeKind::Updated,
            parent_id,
            previous_parent_id: None,
        }
    }

    pub fn deleted(node_id: Uuid, node_kind: NodeKind, parent_id: Option<Uuid>) -> Self {
        Self {
            node_id,
            node_kind,
            change: ConnectionNodeChangeKind::Deleted,
            parent_id,
            previous_parent_id: None,
        }
    }

    pub fn reparented(
        node_id: Uuid,
        node_kind: NodeKind,
        previous_parent_id: Option<Uuid>,
        new_parent_id: Option<Uuid>,
    ) -> Self {
        Self {
            node_id,
            node_kind,
            change: ConnectionNodeChangeKind::Reparented,
            parent_id: new_parent_id,
            previous_parent_id,
        }
    }

    /// Strip a domain row to an Updated event (C# `PublishConnectionNodeUpdated` shape).
    pub fn updated_from_node(node: &ConnectionNode) -> Self {
        Self::updated(node.id, node.kind, node.parent_id)
    }

    pub fn created_from_node(node: &ConnectionNode) -> Self {
        Self::created(node.id, node.kind, node.parent_id)
    }

    pub fn deleted_from_node(node: &ConnectionNode) -> Self {
        Self::deleted(node.id, node.kind, node.parent_id)
    }

    pub fn reparented_from_node(node: &ConnectionNode, previous_parent_id: Option<Uuid>) -> Self {
        Self::reparented(node.id, node.kind, previous_parent_id, node.parent_id)
    }

    /// Create / delete / reparent need a full tree reload; update can patch in place
    /// (C# `ApplyConnectionNodeUpdated`). Structural parent moves must publish
    /// [`ConnectionNodeChangeKind::Reparented`], not Updated — Updated keeps
    /// `suggests_tree_reload() == false`.
    pub fn suggests_tree_reload(&self) -> bool {
        !matches!(self.change, ConnectionNodeChangeKind::Updated)
    }

    /// Open session tabs should carefully re-resolve profiles after update /
    /// delete / reparent (folder changes may affect descendant inheritance).
    /// Created is tree-only — no open session for a brand-new id yet.
    pub fn suggests_session_profile_refresh(&self) -> bool {
        !matches!(self.change, ConnectionNodeChangeKind::Created)
    }

    /// True when this event is about `node_id` itself.
    pub fn affects_node(&self, node_id: Uuid) -> bool {
        self.node_id == node_id
    }

    /// Folder mutations that suggest profile refresh may affect descendant sessions.
    pub fn may_affect_descendant_sessions(&self) -> bool {
        self.node_kind == NodeKind::Folder && self.suggests_session_profile_refresh()
    }
}

/// Opaque subscription handle returned by [`ConnectionNodeChangeNotifier::subscribe`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConnectionNodeChangeSubscription(u64);

impl ConnectionNodeChangeSubscription {
    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

/// Callback invoked after each published event (lock released before call).
pub type ConnectionNodeChangeCallback = Arc<dyn Fn(&ConnectionNodeChangeEvent) + Send + Sync>;

/// Pub/sub for connection / folder row changes.
pub trait ConnectionNodeChangeNotifier: Send + Sync {
    fn publish(&self, event: ConnectionNodeChangeEvent);

    fn subscribe(&self, listener: ConnectionNodeChangeCallback) -> ConnectionNodeChangeSubscription;

    /// Remove a prior subscription. Returns `true` when the id was known.
    fn unsubscribe(&self, id: ConnectionNodeChangeSubscription) -> bool;
}

/// Convenience publish helpers (metadata only).
pub trait ConnectionNodeChangePublisher: ConnectionNodeChangeNotifier {
    fn publish_created(&self, node_id: Uuid, node_kind: NodeKind, parent_id: Option<Uuid>) {
        self.publish(ConnectionNodeChangeEvent::created(
            node_id, node_kind, parent_id,
        ));
    }

    fn publish_updated(&self, node_id: Uuid, node_kind: NodeKind, parent_id: Option<Uuid>) {
        self.publish(ConnectionNodeChangeEvent::updated(
            node_id, node_kind, parent_id,
        ));
    }

    fn publish_deleted(&self, node_id: Uuid, node_kind: NodeKind, parent_id: Option<Uuid>) {
        self.publish(ConnectionNodeChangeEvent::deleted(
            node_id, node_kind, parent_id,
        ));
    }

    fn publish_reparented(
        &self,
        node_id: Uuid,
        node_kind: NodeKind,
        previous_parent_id: Option<Uuid>,
        new_parent_id: Option<Uuid>,
    ) {
        self.publish(ConnectionNodeChangeEvent::reparented(
            node_id,
            node_kind,
            previous_parent_id,
            new_parent_id,
        ));
    }

    fn publish_updated_from_node(&self, node: &ConnectionNode) {
        self.publish(ConnectionNodeChangeEvent::updated_from_node(node));
    }
}

impl<T: ConnectionNodeChangeNotifier + ?Sized> ConnectionNodeChangePublisher for T {}

/// No-op notifier (lab / hosts without live tree refresh wiring).
#[derive(Debug, Default, Clone, Copy)]
pub struct NopConnectionNodeChangeNotifier;

impl ConnectionNodeChangeNotifier for NopConnectionNodeChangeNotifier {
    fn publish(&self, _event: ConnectionNodeChangeEvent) {}

    fn subscribe(
        &self,
        _listener: ConnectionNodeChangeCallback,
    ) -> ConnectionNodeChangeSubscription {
        ConnectionNodeChangeSubscription(0)
    }

    fn unsubscribe(&self, _id: ConnectionNodeChangeSubscription) -> bool {
        false
    }
}

struct FakeInner {
    events: Vec<ConnectionNodeChangeEvent>,
    subscribers: Vec<(ConnectionNodeChangeSubscription, ConnectionNodeChangeCallback)>,
    next_id: u64,
    /// True while a top-level fan-out is running; nested `publish` enqueues.
    dispatching: bool,
    pending: VecDeque<ConnectionNodeChangeEvent>,
}

/// In-memory pub/sub Fake: records every event and fans out to subscribers.
///
/// Subscribers (tree reload / session profile refresh) run **after** the event
/// is appended and **outside** the internal lock so a callback may publish
/// again without deadlocking. Nested publishes are **queued** and delivered
/// only after the current fan-out finishes, so later subscribers still see
/// events in record order (Created before a nested Updated).
#[derive(Clone, Default)]
pub struct FakeConnectionNodeChangeNotifier {
    inner: Arc<Mutex<FakeInner>>,
}

impl FakeConnectionNodeChangeNotifier {
    pub fn new() -> Self {
        Self::default()
    }

    fn with_inner<R>(&self, f: impl FnOnce(&mut FakeInner) -> R) -> R {
        let mut guard = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        f(&mut guard)
    }

    /// Snapshot of recorded events (order preserved).
    pub fn events(&self) -> Vec<ConnectionNodeChangeEvent> {
        self.with_inner(|inner| inner.events.clone())
    }

    pub fn len(&self) -> usize {
        self.with_inner(|inner| inner.events.len())
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Clear the recorded event log. Does not remove subscribers or abort an
    /// in-flight fan-out / nested pending queue.
    pub fn clear(&self) {
        self.with_inner(|inner| inner.events.clear());
    }

    /// Active subscriber count (does not include unsubscribed ids).
    pub fn subscriber_count(&self) -> usize {
        self.with_inner(|inner| inner.subscribers.len())
    }

    /// Test / adversarial helper: force the next minted subscription id.
    #[doc(hidden)]
    pub fn force_next_subscription_id_for_test(&self, next_id: u64) {
        self.with_inner(|inner| inner.next_id = next_id);
    }
}

impl Default for FakeInner {
    fn default() -> Self {
        Self {
            events: Vec::new(),
            subscribers: Vec::new(),
            // 0 is reserved for [`NopConnectionNodeChangeNotifier`].
            next_id: 1,
            dispatching: false,
            pending: VecDeque::new(),
        }
    }
}

impl FakeInner {
    /// Next free id among active subscribers; wraps and skips `0` (Nop sentinel).
    ///
    /// Plain `saturating_add` would mint duplicate `u64::MAX` ids forever, so a
    /// single `unsubscribe` could drop every colliding subscription at once.
    fn mint_subscription_id(&mut self) -> ConnectionNodeChangeSubscription {
        loop {
            let candidate = self.next_id;
            self.next_id = self.next_id.wrapping_add(1);
            if self.next_id == 0 {
                self.next_id = 1;
            }
            if candidate == 0 {
                continue;
            }
            if self.subscribers.iter().any(|(sid, _)| sid.0 == candidate) {
                continue;
            }
            return ConnectionNodeChangeSubscription(candidate);
        }
    }
}

impl fmt::Debug for FakeConnectionNodeChangeNotifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.with_inner(|inner| {
            f.debug_struct("FakeConnectionNodeChangeNotifier")
                .field("events", &inner.events.len())
                .field("subscribers", &inner.subscribers.len())
                .finish()
        })
    }
}

impl ConnectionNodeChangeNotifier for FakeConnectionNodeChangeNotifier {
    fn publish(&self, event: ConnectionNodeChangeEvent) {
        enum PublishAction {
            /// Nested publish while a fan-out is already running — already queued.
            Deferred,
            /// Take ownership of the fan-out loop (including any nested queue).
            Dispatch(ConnectionNodeChangeEvent),
        }

        let action = self.with_inner(|inner| {
            inner.events.push(event.clone());
            if inner.dispatching {
                inner.pending.push_back(event);
                PublishAction::Deferred
            } else {
                inner.dispatching = true;
                PublishAction::Dispatch(event)
            }
        });

        let PublishAction::Dispatch(mut current) = action else {
            return;
        };

        loop {
            let callbacks = self.with_inner(|inner| {
                inner
                    .subscribers
                    .iter()
                    .map(|(_, cb)| Arc::clone(cb))
                    .collect::<Vec<_>>()
            });
            for cb in callbacks {
                cb(&current);
            }

            // Clear `dispatching` only while holding the lock with an empty
            // pending queue — otherwise a concurrent publish can enqueue and
            // then see `dispatching == false`, stranding the nested event.
            let next = self.with_inner(|inner| {
                if let Some(event) = inner.pending.pop_front() {
                    Some(event)
                } else {
                    inner.dispatching = false;
                    None
                }
            });
            match next {
                Some(event) => current = event,
                None => break,
            }
        }
    }

    fn subscribe(&self, listener: ConnectionNodeChangeCallback) -> ConnectionNodeChangeSubscription {
        self.with_inner(|inner| {
            let id = inner.mint_subscription_id();
            inner.subscribers.push((id, listener));
            id
        })
    }

    fn unsubscribe(&self, id: ConnectionNodeChangeSubscription) -> bool {
        self.with_inner(|inner| {
            let before = inner.subscribers.len();
            inner.subscribers.retain(|(sid, _)| *sid != id);
            inner.subscribers.len() != before
        })
    }
}

/// Shared handle alias for DI / composition roots.
pub type SharedConnectionNodeChangeNotifier = Arc<dyn ConnectionNodeChangeNotifier>;

#[derive(Debug, Default)]
struct RefreshListenerState {
    events: Vec<ConnectionNodeChangeEvent>,
    tree_reloads: usize,
    profile_refreshes: usize,
}

/// Test helper: records refresh hints a tree / session host would act on.
#[derive(Debug, Default, Clone)]
pub struct RecordingRefreshListener {
    state: Arc<Mutex<RefreshListenerState>>,
}

impl RecordingRefreshListener {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn callback(&self) -> ConnectionNodeChangeCallback {
        let state = Arc::clone(&self.state);
        Arc::new(move |event: &ConnectionNodeChangeEvent| {
            let mut guard = state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            guard.events.push(event.clone());
            if event.suggests_tree_reload() {
                guard.tree_reloads = guard.tree_reloads.saturating_add(1);
            }
            if event.suggests_session_profile_refresh() {
                guard.profile_refreshes = guard.profile_refreshes.saturating_add(1);
            }
        })
    }

    pub fn recorded_events(&self) -> Vec<ConnectionNodeChangeEvent> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .events
            .clone()
    }

    pub fn tree_reload_count(&self) -> usize {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .tree_reloads
    }

    pub fn profile_refresh_count(&self) -> usize {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .profile_refreshes
    }
}
