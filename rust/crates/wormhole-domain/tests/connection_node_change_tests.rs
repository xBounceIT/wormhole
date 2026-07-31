//! Connection / folder change notifier Fake glue tests.

use std::sync::{Arc, Mutex};

use uuid::Uuid;
use wormhole_domain::{
    ConnectionNode, ConnectionNodeChangeEvent, ConnectionNodeChangeKind,
    ConnectionNodeChangeNotifier, ConnectionNodeChangePublisher, FakeConnectionNodeChangeNotifier,
    NodeKind, NopConnectionNodeChangeNotifier, RecordingRefreshListener,
};

fn node(id: Uuid, kind: NodeKind, parent_id: Option<Uuid>) -> ConnectionNode {
    ConnectionNode {
        id,
        parent_id,
        kind,
        name: "n".into(),
        ..ConnectionNode::default()
    }
}

#[test]
fn fake_records_create_update_delete_reparent() {
    let fake = FakeConnectionNodeChangeNotifier::new();
    let folder = Uuid::new_v4();
    let leaf = Uuid::new_v4();
    let other = Uuid::new_v4();

    fake.publish_created(folder, NodeKind::Folder, None);
    fake.publish_created(leaf, NodeKind::Connection, Some(folder));
    fake.publish_updated(leaf, NodeKind::Connection, Some(folder));
    fake.publish_reparented(leaf, NodeKind::Connection, Some(folder), Some(other));
    fake.publish_deleted(leaf, NodeKind::Connection, Some(other));

    let events = fake.events();
    assert_eq!(events.len(), 5);
    assert_eq!(events[0].change, ConnectionNodeChangeKind::Created);
    assert_eq!(events[0].node_kind, NodeKind::Folder);
    assert_eq!(events[1].parent_id, Some(folder));
    assert_eq!(events[2].change, ConnectionNodeChangeKind::Updated);
    assert_eq!(events[3].change, ConnectionNodeChangeKind::Reparented);
    assert_eq!(events[3].previous_parent_id, Some(folder));
    assert_eq!(events[3].parent_id, Some(other));
    assert_eq!(events[4].change, ConnectionNodeChangeKind::Deleted);
}

#[test]
fn updated_from_node_strips_to_metadata_only() {
    let id = Uuid::new_v4();
    let parent = Uuid::new_v4();
    let mut n = node(id, NodeKind::Connection, Some(parent));
    n.name = "prod-ssh".into();
    n.host = Some("secret.example".into());
    n.username = Some("admin".into());
    n.use_inline_password = Some(true);
    // Domain rows never carry password bytes; event must still be ids-only.
    let event = ConnectionNodeChangeEvent::updated_from_node(&n);
    assert_eq!(
        event,
        ConnectionNodeChangeEvent::updated(id, NodeKind::Connection, Some(parent))
    );
    let debug = format!("{event:?}");
    assert!(!debug.contains("admin"));
    assert!(!debug.contains("secret.example"));
    assert!(!debug.contains("prod-ssh"));
}

#[test]
fn subscribers_receive_events_and_can_refresh() {
    let fake = FakeConnectionNodeChangeNotifier::new();
    let listener = RecordingRefreshListener::new();
    let sub = fake.subscribe(listener.callback());

    let folder = Uuid::new_v4();
    let leaf = Uuid::new_v4();
    fake.publish_created(leaf, NodeKind::Connection, Some(folder));
    fake.publish_updated_from_node(&node(leaf, NodeKind::Connection, Some(folder)));
    fake.publish_reparented(leaf, NodeKind::Connection, Some(folder), None);
    fake.publish_deleted(folder, NodeKind::Folder, None);

    assert_eq!(fake.len(), 4);
    assert_eq!(listener.recorded_events().len(), 4);
    // Created → tree only; Updated → profile only; Reparented/Deleted → both.
    assert_eq!(listener.tree_reload_count(), 3); // create, reparent, delete
    assert_eq!(listener.profile_refresh_count(), 3); // update, reparent, delete

    assert!(fake.unsubscribe(sub));
    assert_eq!(fake.subscriber_count(), 0);
    fake.publish_updated(leaf, NodeKind::Connection, None);
    assert_eq!(fake.len(), 5);
    assert_eq!(listener.recorded_events().len(), 4); // unsubscribed
}

#[test]
fn refresh_hints_match_change_kind() {
    let id = Uuid::new_v4();
    let created = ConnectionNodeChangeEvent::created(id, NodeKind::Connection, None);
    assert!(created.suggests_tree_reload());
    assert!(!created.suggests_session_profile_refresh());

    let updated = ConnectionNodeChangeEvent::updated(id, NodeKind::Connection, None);
    assert!(!updated.suggests_tree_reload());
    assert!(updated.suggests_session_profile_refresh());
    assert!(updated.affects_node(id));

    let folder_updated =
        ConnectionNodeChangeEvent::updated(id, NodeKind::Folder, None);
    assert!(folder_updated.may_affect_descendant_sessions());

    let deleted = ConnectionNodeChangeEvent::deleted(id, NodeKind::Connection, None);
    assert!(deleted.suggests_tree_reload());
    assert!(deleted.suggests_session_profile_refresh());

    let reparented = ConnectionNodeChangeEvent::reparented(id, NodeKind::Folder, None, Some(Uuid::new_v4()));
    assert!(reparented.suggests_tree_reload());
    assert!(reparented.suggests_session_profile_refresh());
    assert!(reparented.may_affect_descendant_sessions());
}

#[test]
fn publish_during_callback_does_not_deadlock() {
    let fake = FakeConnectionNodeChangeNotifier::new();
    let nested = Arc::new(Mutex::new(false));
    let nested_flag = Arc::clone(&nested);
    let fake_cb = fake.clone();
    fake.subscribe(Arc::new(move |event| {
        if event.change == ConnectionNodeChangeKind::Created {
            fake_cb.publish_updated(event.node_id, event.node_kind, event.parent_id);
            *nested_flag
                .lock()
                .unwrap_or_else(|p| p.into_inner()) = true;
        }
    }));

    let id = Uuid::new_v4();
    fake.publish_created(id, NodeKind::Connection, None);
    assert!(*nested.lock().unwrap_or_else(|p| p.into_inner()));
    assert_eq!(fake.len(), 2);
    assert_eq!(fake.events()[1].change, ConnectionNodeChangeKind::Updated);
}

#[test]
fn nested_publish_preserves_delivery_order_for_later_subscribers() {
    let fake = FakeConnectionNodeChangeNotifier::new();
    let order = Arc::new(Mutex::new(Vec::new()));

    let order_a = Arc::clone(&order);
    let fake_a = fake.clone();
    fake.subscribe(Arc::new(move |event| {
        order_a
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(format!("a:{:?}", event.change));
        if event.change == ConnectionNodeChangeKind::Created {
            fake_a.publish_updated(event.node_id, event.node_kind, event.parent_id);
        }
    }));

    let order_b = Arc::clone(&order);
    fake.subscribe(Arc::new(move |event| {
        order_b
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(format!("b:{:?}", event.change));
    }));

    fake.publish_created(Uuid::new_v4(), NodeKind::Connection, None);
    assert_eq!(
        *order.lock().unwrap_or_else(|p| p.into_inner()),
        vec![
            "a:Created".to_string(),
            "b:Created".to_string(),
            "a:Updated".to_string(),
            "b:Updated".to_string(),
        ]
    );
}

#[test]
fn nop_notifier_swallows_publish_and_subscribe() {
    let nop = NopConnectionNodeChangeNotifier;
    let id = nop.subscribe(Arc::new(|_| panic!("nop must not invoke listeners")));
    nop.publish_created(Uuid::new_v4(), NodeKind::Folder, None);
    assert!(!nop.unsubscribe(id));
}

#[test]
fn fake_debug_omits_event_payload_bodies() {
    let fake = FakeConnectionNodeChangeNotifier::new();
    fake.publish_updated(Uuid::new_v4(), NodeKind::Connection, None);
    let debug = format!("{fake:?}");
    assert!(debug.contains("events: 1"));
    assert!(debug.contains("subscribers: 0"));
    // Counts only — no node UUID dump required in Debug summary.
}

#[test]
fn from_node_helpers_and_hint_negatives() {
    let id = Uuid::new_v4();
    let parent = Uuid::new_v4();
    let prev = Uuid::new_v4();
    let n = node(id, NodeKind::Folder, Some(parent));

    assert_eq!(
        ConnectionNodeChangeEvent::created_from_node(&n),
        ConnectionNodeChangeEvent::created(id, NodeKind::Folder, Some(parent))
    );
    assert_eq!(
        ConnectionNodeChangeEvent::deleted_from_node(&n),
        ConnectionNodeChangeEvent::deleted(id, NodeKind::Folder, Some(parent))
    );
    assert_eq!(
        ConnectionNodeChangeEvent::reparented_from_node(&n, Some(prev)),
        ConnectionNodeChangeEvent::reparented(id, NodeKind::Folder, Some(prev), Some(parent))
    );

    let conn_updated = ConnectionNodeChangeEvent::updated(id, NodeKind::Connection, None);
    assert!(!conn_updated.may_affect_descendant_sessions());
    assert!(!conn_updated.affects_node(Uuid::new_v4()));

    let folder_created = ConnectionNodeChangeEvent::created(id, NodeKind::Folder, None);
    assert!(!folder_created.may_affect_descendant_sessions());
    assert!(folder_created.previous_parent_id.is_none());
}

#[test]
fn change_kind_display_labels() {
    assert_eq!(ConnectionNodeChangeKind::Created.to_string(), "Created");
    assert_eq!(ConnectionNodeChangeKind::Updated.to_string(), "Updated");
    assert_eq!(ConnectionNodeChangeKind::Deleted.to_string(), "Deleted");
    assert_eq!(ConnectionNodeChangeKind::Reparented.to_string(), "Reparented");
}

#[test]
fn mid_publish_subscribe_misses_current_event() {
    let fake = FakeConnectionNodeChangeNotifier::new();
    let late = RecordingRefreshListener::new();
    let late_cb = late.callback();
    let fake_cb = fake.clone();
    fake.subscribe(Arc::new(move |_| {
        let _ = fake_cb.subscribe(Arc::clone(&late_cb));
    }));

    fake.publish_created(Uuid::new_v4(), NodeKind::Connection, None);
    assert_eq!(fake.subscriber_count(), 2);
    assert!(late.recorded_events().is_empty()); // snapshot before late subscribe
    fake.publish_updated(Uuid::new_v4(), NodeKind::Connection, None);
    assert_eq!(late.recorded_events().len(), 1);
    assert_eq!(
        late.recorded_events()[0].change,
        ConnectionNodeChangeKind::Updated
    );
}

#[test]
fn multi_subscriber_fanout_is_insertion_order() {
    let fake = FakeConnectionNodeChangeNotifier::new();
    let order = Arc::new(Mutex::new(Vec::new()));
    for label in ["a", "b", "c"] {
        let order = Arc::clone(&order);
        let tag = label.to_string();
        fake.subscribe(Arc::new(move |_| {
            order
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .push(tag.clone());
        }));
    }
    fake.publish_deleted(Uuid::new_v4(), NodeKind::Folder, None);
    assert_eq!(
        *order.lock().unwrap_or_else(|p| p.into_inner()),
        vec!["a".to_string(), "b".to_string(), "c".to_string()]
    );
}

#[test]
fn unsubscribe_is_idempotent_and_clear_keeps_subscribers() {
    let fake = FakeConnectionNodeChangeNotifier::new();
    let listener = RecordingRefreshListener::new();
    let sub = fake.subscribe(listener.callback());
    assert!(fake.unsubscribe(sub));
    assert!(!fake.unsubscribe(sub));
    assert_eq!(fake.subscriber_count(), 0);

    let sub2 = fake.subscribe(listener.callback());
    fake.publish_updated(Uuid::new_v4(), NodeKind::Connection, None);
    assert_eq!(fake.len(), 1);
    fake.clear();
    assert!(fake.is_empty());
    assert_eq!(fake.subscriber_count(), 1);
    assert!(fake.unsubscribe(sub2));
}

#[test]
fn subscription_ids_skip_collision_at_u64_max() {
    let fake = FakeConnectionNodeChangeNotifier::new();
    fake.force_next_subscription_id_for_test(u64::MAX);
    let a = fake.subscribe(Arc::new(|_| {}));
    let b = fake.subscribe(Arc::new(|_| {}));
    assert_eq!(a.as_u64(), u64::MAX);
    // Must not mint a second MAX (would make one unsubscribe drop both).
    assert_ne!(b.as_u64(), u64::MAX);
    assert_ne!(b.as_u64(), 0); // Nop sentinel reserved
    assert!(fake.unsubscribe(a));
    assert_eq!(fake.subscriber_count(), 1);
    assert!(fake.unsubscribe(b));
}

#[test]
fn shared_notifier_publisher_helpers_work() {
    let fake = FakeConnectionNodeChangeNotifier::new();
    let shared: wormhole_domain::SharedConnectionNodeChangeNotifier = Arc::new(fake.clone());
    let id = Uuid::new_v4();
    shared.publish_created(id, NodeKind::Connection, None);
    shared.publish_updated_from_node(&node(id, NodeKind::Connection, None));
    assert_eq!(fake.len(), 2);
    assert_eq!(fake.events()[0].change, ConnectionNodeChangeKind::Created);
    assert_eq!(fake.events()[1].change, ConnectionNodeChangeKind::Updated);
}

#[test]
fn concurrent_publish_delivers_every_recorded_event() {
    let fake = FakeConnectionNodeChangeNotifier::new();
    let delivered = Arc::new(Mutex::new(0usize));
    let delivered_cb = Arc::clone(&delivered);
    fake.subscribe(Arc::new(move |_| {
        *delivered_cb
            .lock()
            .unwrap_or_else(|p| p.into_inner()) += 1;
    }));

    const THREADS: usize = 8;
    const PER_THREAD: usize = 64;
    let mut handles = Vec::with_capacity(THREADS);
    for _ in 0..THREADS {
        let fake = fake.clone();
        handles.push(std::thread::spawn(move || {
            for _ in 0..PER_THREAD {
                fake.publish_updated(Uuid::new_v4(), NodeKind::Connection, None);
            }
        }));
    }
    for handle in handles {
        handle.join().expect("publisher thread");
    }

    let expected = THREADS * PER_THREAD;
    assert_eq!(fake.len(), expected);
    assert_eq!(
        *delivered.lock().unwrap_or_else(|p| p.into_inner()),
        expected,
        "every recorded event must fan out (no stranded nested/concurrent publish)"
    );
}
