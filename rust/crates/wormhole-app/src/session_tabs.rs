//! Pure-state glue: [`wormhole_session::SessionId`] ↔ [`wormhole_ui::SessionTabBarState`].
//!
//! No GPUI window — maps orchestrator ids onto the session tab strip. User tab close
//! cancels in-flight connect + disposes [`SessionHandle`] (tunnel lease drop).
//! [`SessionBindings::attach_handle`] after `connect` disposes orphans when the binding
//! was removed mid-connect, and fail-closes on a second attach.
//! See `docs/migration/08-ui.md` and `docs/migration/16-session-orchestrator.md`.

use std::collections::HashMap;

use thiserror::Error;
use uuid::Uuid;
use wormhole_domain::ProtocolType;
use wormhole_session::{CancellationToken, SessionHandle, SessionId};
use wormhole_ui::{ProtocolBadge, SessionTabBarState, UiError};

/// Convert an orchestrator [`SessionId`] into the UI tab-bar newtype (same UUID bits).
#[inline]
pub fn to_ui_session_id(id: SessionId) -> wormhole_ui::SessionId {
    wormhole_ui::SessionId::from_uuid(id.as_uuid())
}

/// Convert a UI tab-bar id back to the orchestrator [`SessionId`] (same UUID bits).
#[inline]
pub fn from_ui_session_id(id: wormhole_ui::SessionId) -> SessionId {
    SessionId::from_uuid(id.as_uuid())
}

/// Open (and activate) a tab for `session_id`.
///
/// Fails with [`UiError::DuplicateSession`] if the id is already open (state unchanged).
/// Titles follow [`SessionTabBarState::open`] soft-sanitize rules.
pub fn open_tab_for_session(
    bar: &mut SessionTabBarState,
    session_id: SessionId,
    title: impl Into<String>,
    protocol: ProtocolType,
) -> Result<(), UiError> {
    bar.open(
        to_ui_session_id(session_id),
        title,
        ProtocolBadge::from_protocol(protocol),
    )
}

/// Close the tab when a session ends.
///
/// Idempotent: [`UiError::UnknownSession`] (tab already gone) is treated as success so
/// closed-event handlers can fire more than once without fail-open side effects.
pub fn close_tab_on_session_closed(
    bar: &mut SessionTabBarState,
    session_id: SessionId,
) -> Result<(), UiError> {
    match bar.close(to_ui_session_id(session_id)) {
        Ok(()) | Err(UiError::UnknownSession(_)) => Ok(()),
        Err(e) => Err(e),
    }
}

/// Errors from tab-close → orchestrator dispose glue.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum SessionTabGlueError {
    #[error(transparent)]
    Ui(#[from] UiError),
    /// Caller passed a [`SessionHandle`] whose id does not match the tab being closed.
    #[error("session handle id mismatch: expected {expected}, got {actual}")]
    HandleIdMismatch { expected: Uuid, actual: Uuid },
    /// [`SessionBindings`] already tracks this id (fail-closed; state unchanged).
    #[error("session binding already registered: {0}")]
    DuplicateBinding(Uuid),
}

/// Cancel token + optional live handle for one open session tab.
pub struct SessionBinding {
    cancel: CancellationToken,
    handle: Option<SessionHandle>,
}

impl SessionBinding {
    pub fn connecting(cancel: CancellationToken) -> Self {
        Self {
            cancel,
            handle: None,
        }
    }

    pub fn connected(handle: SessionHandle, cancel: CancellationToken) -> Self {
        Self {
            cancel,
            handle: Some(handle),
        }
    }

    pub fn cancel(&self) -> &CancellationToken {
        &self.cancel
    }

    pub fn handle(&self) -> Option<&SessionHandle> {
        self.handle.as_ref()
    }

    pub fn is_connected(&self) -> bool {
        self.handle.is_some()
    }
}

impl std::fmt::Debug for SessionBinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionBinding")
            .field("cancel_is_cancelled", &self.cancel.is_cancelled())
            .field("has_handle", &self.handle.is_some())
            .field("handle_id", &self.handle.as_ref().map(|h| h.id()))
            .finish()
    }
}

/// Composition-root map: orchestrator [`SessionId`] → cancel / handle (no GPUI).
#[derive(Debug, Default)]
pub struct SessionBindings {
    by_id: HashMap<SessionId, SessionBinding>,
}

impl SessionBindings {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.by_id.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_id.is_empty()
    }

    pub fn contains(&self, id: SessionId) -> bool {
        self.by_id.contains_key(&id)
    }

    pub fn get(&self, id: SessionId) -> Option<&SessionBinding> {
        self.by_id.get(&id)
    }

    /// Register a connecting (or connected) binding. Fail-closed on duplicate id.
    pub fn insert(
        &mut self,
        id: SessionId,
        binding: SessionBinding,
    ) -> Result<(), SessionTabGlueError> {
        if self.by_id.contains_key(&id) {
            return Err(SessionTabGlueError::DuplicateBinding(id.as_uuid()));
        }
        if let Some(ref handle) = binding.handle {
            if handle.id() != id {
                return Err(SessionTabGlueError::HandleIdMismatch {
                    expected: id.as_uuid(),
                    actual: handle.id().as_uuid(),
                });
            }
        }
        self.by_id.insert(id, binding);
        Ok(())
    }

    /// Insert after connect: key = `handle.id()`.
    pub fn insert_connected(
        &mut self,
        handle: SessionHandle,
        cancel: CancellationToken,
    ) -> Result<(), SessionTabGlueError> {
        let id = handle.id();
        self.insert(id, SessionBinding::connected(handle, cancel))
    }

    /// Attach the live handle after `connect` returns.
    ///
    /// - Binding present and still connecting → store handle.
    /// - Binding absent (tab closed mid-connect / never registered) →
    ///   [`SessionHandle::close`] (lease drop) then `Ok` — do not leak orphans.
    /// - Binding already has a handle → close the *new* handle, **fail-closed**
    ///   [`SessionTabGlueError::DuplicateBinding`] (existing handle untouched).
    pub async fn attach_handle(
        &mut self,
        handle: SessionHandle,
    ) -> Result<(), SessionTabGlueError> {
        let id = handle.id();
        match self.by_id.get_mut(&id) {
            None => {
                handle.close().await;
                Ok(())
            }
            Some(binding) if binding.handle.is_some() => {
                handle.close().await;
                Err(SessionTabGlueError::DuplicateBinding(id.as_uuid()))
            }
            Some(binding) => {
                binding.handle = Some(handle);
                Ok(())
            }
        }
    }
}

/// User closed a session tab: remove chrome, cancel in-flight connect, dispose handle.
///
/// Order: validate handle id (fail-closed) → [`close_tab_on_session_closed`] (idempotent) →
/// cancel token → [`SessionHandle::close`] (drops tunnel lease).
///
/// Pass `handle: None` + `cancel: Some` to abort a connect that has not returned yet.
pub async fn close_tab_and_dispose(
    bar: &mut SessionTabBarState,
    session_id: SessionId,
    handle: Option<SessionHandle>,
    cancel: Option<&CancellationToken>,
) -> Result<(), SessionTabGlueError> {
    if let Some(ref h) = handle {
        if h.id() != session_id {
            return Err(SessionTabGlueError::HandleIdMismatch {
                expected: session_id.as_uuid(),
                actual: h.id().as_uuid(),
            });
        }
    }

    close_tab_on_session_closed(bar, session_id)?;

    if let Some(token) = cancel {
        token.cancel();
    }

    if let Some(handle) = handle {
        handle.close().await;
    }

    Ok(())
}

/// Lookup-by-id variant: close tab + cancel/dispose the [`SessionBindings`] entry.
///
/// Unknown binding is a no-op after the (idempotent) tab close — safe for replayed closes.
pub async fn close_tab_and_dispose_session(
    bar: &mut SessionTabBarState,
    bindings: &mut SessionBindings,
    session_id: SessionId,
) -> Result<(), SessionTabGlueError> {
    let (handle, cancel) = match bindings.by_id.remove(&session_id) {
        Some(b) => (b.handle, Some(b.cancel)),
        None => (None, None),
    };
    close_tab_and_dispose(bar, session_id, handle, cancel.as_ref()).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::time::Duration;
    use uuid::Uuid;
    use wormhole_domain::{ConnectionProfile, ProtocolType};
    use wormhole_session::{
        ConnectOptions, FakeSerialConnector, FakeSshConnector, FakeTunnelBroker,
        SessionOrchestrator, SessionState, TunnelBroker, TunnelConnectArgs,
    };
    use wormhole_tunnels::{TunnelConfigSnapshot, TunnelKind, TunnelManager};
    use wormhole_ui::SessionTabBarState;

    /// Fake orchestrator ids — no live connect.
    fn fake_id() -> SessionId {
        SessionId::new()
    }

    #[test]
    fn id_round_trips_ui_newtype() {
        for bits in [Uuid::nil(), Uuid::from_u128(u128::MAX), Uuid::new_v4()] {
            let orch = SessionId::from_uuid(bits);
            let ui = to_ui_session_id(orch);
            assert_eq!(ui.as_uuid(), bits);
            assert_eq!(ui.as_uuid(), orch.as_uuid());
            assert_eq!(from_ui_session_id(ui), orch);
            // Bits only — no remapping / hashing; pub-field and from_uuid agree.
            assert_eq!(SessionId::from_uuid(ui.0), orch);
            assert_eq!(from_ui_session_id(to_ui_session_id(orch)), orch);
            assert_eq!(to_ui_session_id(from_ui_session_id(ui)), ui);
        }
    }

    #[test]
    fn open_tab_for_session_maps_protocol_and_activates() {
        let mut bar = SessionTabBarState::new();
        let a = fake_id();
        let b = fake_id();

        open_tab_for_session(&mut bar, a, "prod / web-1", ProtocolType::Ssh).unwrap();
        assert_eq!(bar.len(), 1);
        assert_eq!(bar.active_id(), Some(to_ui_session_id(a)));
        assert_eq!(bar.active_tab().unwrap().badge, ProtocolBadge::Ssh);
        assert_eq!(bar.active_tab().unwrap().title, "prod / web-1");

        open_tab_for_session(&mut bar, b, "dc", ProtocolType::Rdp).unwrap();
        assert_eq!(bar.len(), 2);
        assert_eq!(bar.active_id(), Some(to_ui_session_id(b)));
        assert_eq!(bar.active_tab().unwrap().badge, ProtocolBadge::Rdp);
    }

    #[test]
    fn open_duplicate_fail_closed() {
        let mut bar = SessionTabBarState::new();
        let id = fake_id();
        open_tab_for_session(&mut bar, id, "first", ProtocolType::Https).unwrap();
        let before = bar.clone();
        assert_eq!(
            open_tab_for_session(&mut bar, id, "again", ProtocolType::Ssh),
            Err(UiError::DuplicateSession(id.as_uuid()))
        );
        assert_eq!(bar.tabs(), before.tabs());
        assert_eq!(bar.active_id(), before.active_id());
        assert_eq!(bar.active_tab().unwrap().title, "first");
        assert_eq!(bar.active_tab().unwrap().badge, ProtocolBadge::Https);
    }

    #[test]
    fn open_empty_title_allowed() {
        let mut bar = SessionTabBarState::new();
        let id = fake_id();
        open_tab_for_session(&mut bar, id, "", ProtocolType::Http).unwrap();
        assert_eq!(bar.get(to_ui_session_id(id)).unwrap().title, "");
        // All-controls soft-sanitize to empty — never Err.
        let id2 = fake_id();
        open_tab_for_session(&mut bar, id2, "\0\u{001f}\u{007f}", ProtocolType::Vnc).unwrap();
        assert_eq!(bar.get(to_ui_session_id(id2)).unwrap().title, "");
    }

    #[test]
    fn close_tab_on_session_closed_removes_and_picks_neighbor() {
        let mut bar = SessionTabBarState::new();
        let a = fake_id();
        let b = fake_id();
        let c = fake_id();
        open_tab_for_session(&mut bar, a, "A", ProtocolType::Ssh).unwrap();
        open_tab_for_session(&mut bar, b, "B", ProtocolType::Vnc).unwrap();
        open_tab_for_session(&mut bar, c, "C", ProtocolType::Http).unwrap();
        // Leave C active; close middle → neighbor at index (C).
        bar.activate(to_ui_session_id(b)).unwrap();
        close_tab_on_session_closed(&mut bar, b).unwrap();
        assert_eq!(bar.len(), 2);
        assert!(!bar.contains(to_ui_session_id(b)));
        assert_eq!(bar.active_id(), Some(to_ui_session_id(c)));
    }

    #[test]
    fn close_background_keeps_active() {
        let mut bar = SessionTabBarState::new();
        let a = fake_id();
        let b = fake_id();
        open_tab_for_session(&mut bar, a, "A", ProtocolType::Ssh).unwrap();
        open_tab_for_session(&mut bar, b, "B", ProtocolType::Rdp).unwrap();
        assert_eq!(bar.active_id(), Some(to_ui_session_id(b)));
        // Re-entrant pure-state sequence: close non-active while B stays active.
        close_tab_on_session_closed(&mut bar, a).unwrap();
        assert_eq!(bar.len(), 1);
        assert_eq!(bar.active_id(), Some(to_ui_session_id(b)));
        assert!(!bar.contains(to_ui_session_id(a)));
    }

    #[test]
    fn close_tab_on_session_closed_is_idempotent() {
        let mut bar = SessionTabBarState::new();
        let id = fake_id();
        open_tab_for_session(&mut bar, id, "solo", ProtocolType::Serial).unwrap();
        close_tab_on_session_closed(&mut bar, id).unwrap();
        assert!(bar.is_empty());
        // Second close (session-closed event replay) must not fail.
        close_tab_on_session_closed(&mut bar, id).unwrap();
        assert!(bar.is_empty());
        assert_eq!(bar.active_id(), None);
    }

    #[test]
    fn reopen_same_id_after_close_succeeds() {
        let mut bar = SessionTabBarState::new();
        let id = fake_id();
        open_tab_for_session(&mut bar, id, "first", ProtocolType::Ssh).unwrap();
        close_tab_on_session_closed(&mut bar, id).unwrap();
        // Third close still Ok (idempotent); then reopen must succeed (not Duplicate).
        close_tab_on_session_closed(&mut bar, id).unwrap();
        open_tab_for_session(&mut bar, id, "again", ProtocolType::Https).unwrap();
        assert_eq!(bar.len(), 1);
        assert_eq!(bar.active_id(), Some(to_ui_session_id(id)));
        assert_eq!(bar.active_tab().unwrap().title, "again");
        assert_eq!(bar.active_tab().unwrap().badge, ProtocolBadge::Https);
    }

    #[test]
    fn close_via_ui_round_trip_id() {
        let mut bar = SessionTabBarState::new();
        let orch = fake_id();
        open_tab_for_session(&mut bar, orch, "round", ProtocolType::Serial).unwrap();
        let back = from_ui_session_id(to_ui_session_id(orch));
        assert_eq!(back, orch);
        close_tab_on_session_closed(&mut bar, back).unwrap();
        assert!(bar.is_empty());
    }

    #[test]
    fn close_unknown_never_opened_is_ok() {
        let mut bar = SessionTabBarState::new();
        let kept = fake_id();
        open_tab_for_session(&mut bar, kept, "kept", ProtocolType::Ssh).unwrap();
        let before = bar.clone();
        close_tab_on_session_closed(&mut bar, fake_id()).unwrap();
        assert_eq!(bar.tabs(), before.tabs());
        assert_eq!(bar.active_id(), before.active_id());
    }

    #[test]
    fn open_soft_sanitizes_hostile_title() {
        let mut bar = SessionTabBarState::new();
        let id = fake_id();
        open_tab_for_session(&mut bar, id, "a\0b\u{0007}c", ProtocolType::Serial).unwrap();
        assert_eq!(bar.get(to_ui_session_id(id)).unwrap().title, "abc");
        assert_eq!(
            bar.get(to_ui_session_id(id)).unwrap().badge,
            ProtocolBadge::Serial
        );
    }

    #[test]
    fn protocol_badge_covers_session_protocols() {
        let mut bar = SessionTabBarState::new();
        let cases = [
            (ProtocolType::Ssh, ProtocolBadge::Ssh),
            (ProtocolType::Rdp, ProtocolBadge::Rdp),
            (ProtocolType::Http, ProtocolBadge::Http),
            (ProtocolType::Https, ProtocolBadge::Https),
            (ProtocolType::Serial, ProtocolBadge::Serial),
            (ProtocolType::Vnc, ProtocolBadge::Vnc),
        ];
        for (protocol, badge) in cases {
            let id = fake_id();
            open_tab_for_session(&mut bar, id, badge.as_str(), protocol).unwrap();
            assert_eq!(bar.get(to_ui_session_id(id)).unwrap().badge, badge);
        }
        assert_eq!(bar.len(), 6);
    }

    #[test]
    fn session_id_debug_is_uuid_only() {
        let secretish = "super-secret-password-value";
        let id = SessionId::from_uuid(Uuid::nil());
        let dbg = format!("{id:?}");
        assert!(dbg.contains("00000000-0000-0000-0000-000000000000"));
        assert!(!dbg.contains(secretish));
        assert!(!format!("{id}").contains(secretish));
    }

    fn http_profile() -> ConnectionProfile {
        ConnectionProfile {
            node_id: Uuid::new_v4(),
            name: "fw".into(),
            protocol: ProtocolType::Http,
            host: "fw.local".into(),
            port: 80,
            ..ConnectionProfile::default()
        }
    }

    fn ssh_profile() -> ConnectionProfile {
        ConnectionProfile {
            node_id: Uuid::new_v4(),
            name: "ssh-box".into(),
            protocol: ProtocolType::Ssh,
            host: "10.0.0.5".into(),
            port: 22,
            username: Some("alice".into()),
            use_inline_password: true,
            ..ConnectionProfile::default()
        }
    }

    fn orch_no_tunnel() -> SessionOrchestrator {
        SessionOrchestrator::for_tests(
            Arc::new(FakeSerialConnector::new()),
            Arc::new(FakeSshConnector::new()),
            None,
        )
    }

    /// SSH over a WireGuard fake broker (connected handle + live lease).
    async fn connect_ssh_with_tunnel() -> (Arc<TunnelManager>, Uuid, SessionHandle, CancellationToken) {
        let tunnel_id = Uuid::new_v4();
        let broker = Arc::new(FakeTunnelBroker::new(TunnelKind::WireGuard));
        let manager = broker.manager();
        let orch = SessionOrchestrator::for_tests(
            Arc::new(FakeSerialConnector::new()),
            Arc::new(FakeSshConnector::new()),
            Some(broker as Arc<dyn TunnelBroker>),
        );
        let mut profile = ssh_profile();
        profile.tunnel_enabled = true;
        profile.tunnel_config_id = Some(tunnel_id);
        let cancel = CancellationToken::new();
        let handle = orch
            .connect(
                profile,
                ConnectOptions {
                    cancel: cancel.clone(),
                    password: Some("x".into()),
                    tunnel: Some(TunnelConnectArgs {
                        config: TunnelConfigSnapshot::new(tunnel_id, TunnelKind::WireGuard, "wg"),
                        secret_blob: Some(b"blob".to_vec()),
                    }),
                    ..ConnectOptions::default()
                },
            )
            .await;
        (manager, tunnel_id, handle, cancel)
    }

    #[tokio::test]
    async fn close_tab_and_dispose_drops_tunnel_lease() {
        let (manager, tunnel_id, handle, cancel) = connect_ssh_with_tunnel().await;
        assert_eq!(handle.state(), SessionState::Connected);
        assert!(handle.tunnel_lease().is_some());
        assert_eq!(manager.pool_ref_count(tunnel_id), 1);

        let id = handle.id();
        let mut bar = SessionTabBarState::new();
        open_tab_for_session(&mut bar, id, "ssh-tun", ProtocolType::Ssh).unwrap();
        let mut bindings = SessionBindings::new();
        bindings
            .insert_connected(handle, cancel)
            .expect("insert connected");

        close_tab_and_dispose_session(&mut bar, &mut bindings, id)
            .await
            .unwrap();
        assert!(bar.is_empty());
        assert!(bindings.is_empty());
        assert_eq!(manager.pool_ref_count(tunnel_id), 0);
    }

    #[tokio::test]
    async fn close_tab_and_dispose_session_is_idempotent() {
        let orch = orch_no_tunnel();
        let handle = orch
            .connect(http_profile(), ConnectOptions::default())
            .await;
        let id = handle.id();
        let mut bar = SessionTabBarState::new();
        open_tab_for_session(&mut bar, id, "http", ProtocolType::Http).unwrap();
        let mut bindings = SessionBindings::new();
        bindings
            .insert_connected(handle, CancellationToken::new())
            .unwrap();

        close_tab_and_dispose_session(&mut bar, &mut bindings, id)
            .await
            .unwrap();
        assert!(bar.is_empty());
        assert!(bindings.is_empty());
        // Replay: unknown tab + unknown binding → Ok.
        close_tab_and_dispose_session(&mut bar, &mut bindings, id)
            .await
            .unwrap();
        assert!(bar.is_empty());
    }

    #[tokio::test]
    async fn close_unknown_binding_is_noop_after_tab_close() {
        let mut bar = SessionTabBarState::new();
        let id = fake_id();
        open_tab_for_session(&mut bar, id, "orphan-tab", ProtocolType::Serial).unwrap();
        let mut bindings = SessionBindings::new();
        close_tab_and_dispose_session(&mut bar, &mut bindings, id)
            .await
            .unwrap();
        assert!(bar.is_empty());
        // Never-registered id: still Ok.
        close_tab_and_dispose_session(&mut bar, &mut bindings, fake_id())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn close_tab_and_dispose_handle_id_mismatch_fail_closed() {
        let orch = orch_no_tunnel();
        let handle = orch
            .connect(http_profile(), ConnectOptions::default())
            .await;
        let wrong_id = fake_id();
        let mut bar = SessionTabBarState::new();
        open_tab_for_session(&mut bar, wrong_id, "wrong", ProtocolType::Http).unwrap();
        let before = bar.clone();
        let err = close_tab_and_dispose(&mut bar, wrong_id, Some(handle), None)
            .await
            .expect_err("mismatch");
        assert!(matches!(err, SessionTabGlueError::HandleIdMismatch { .. }));
        // Fail-closed: tab strip unchanged (validation runs before side effects).
        assert_eq!(bar.tabs(), before.tabs());
        assert_eq!(bar.active_id(), before.active_id());
    }

    #[tokio::test]
    async fn close_during_connect_cancels_and_releases_lease() {
        let tunnel_id = Uuid::new_v4();
        let broker = Arc::new(FakeTunnelBroker::new(TunnelKind::WireGuard));
        let manager = broker.manager();
        let ssh = Arc::new(FakeSshConnector::with_delay(Duration::from_millis(400)));
        let orch = SessionOrchestrator::for_tests(
            Arc::new(FakeSerialConnector::new()),
            Arc::clone(&ssh) as Arc<dyn wormhole_session::SshConnector>,
            Some(broker as Arc<dyn TunnelBroker>),
        );

        let session_id = SessionId::new();
        let cancel = CancellationToken::new();
        let mut bar = SessionTabBarState::new();
        open_tab_for_session(&mut bar, session_id, "connecting", ProtocolType::Ssh).unwrap();
        let mut bindings = SessionBindings::new();
        bindings
            .insert(session_id, SessionBinding::connecting(cancel.clone()))
            .unwrap();

        let mut profile = ssh_profile();
        profile.tunnel_enabled = true;
        profile.tunnel_config_id = Some(tunnel_id);
        let connect = orch.connect(
            profile,
            ConnectOptions {
                cancel: cancel.clone(),
                session_id: Some(session_id),
                password: Some("x".into()),
                tunnel: Some(TunnelConnectArgs {
                    config: TunnelConfigSnapshot::new(tunnel_id, TunnelKind::WireGuard, "wg"),
                    secret_blob: Some(b"blob".to_vec()),
                }),
                ..ConnectOptions::default()
            },
        );

        let closer = async {
            // Let tunnel establish, then user closes the tab mid-SSH.
            tokio::time::sleep(Duration::from_millis(30)).await;
            close_tab_and_dispose_session(&mut bar, &mut bindings, session_id)
                .await
                .unwrap();
        };

        let (handle, _) = tokio::join!(connect, closer);
        assert_eq!(handle.state(), SessionState::Failed);
        assert!(handle.last_error().unwrap().is_cancelled());
        assert!(handle.tunnel_lease().is_none());
        assert_eq!(manager.pool_ref_count(tunnel_id), 0);
        assert!(bar.is_empty());
        assert!(bindings.is_empty());
        // Orphan Failed handle after mid-close: attach_handle disposes (no lease left).
        bindings.attach_handle(handle).await.unwrap();
        assert!(bindings.is_empty());
    }

    #[test]
    fn bindings_duplicate_insert_fail_closed() {
        let mut bindings = SessionBindings::new();
        let id = fake_id();
        bindings
            .insert(id, SessionBinding::connecting(CancellationToken::new()))
            .unwrap();
        let err = bindings
            .insert(id, SessionBinding::connecting(CancellationToken::new()))
            .unwrap_err();
        assert_eq!(err, SessionTabGlueError::DuplicateBinding(id.as_uuid()));
        assert_eq!(bindings.len(), 1);
    }

    #[tokio::test]
    async fn attach_handle_after_connect_then_dispose() {
        let orch = orch_no_tunnel();
        let session_id = SessionId::new();
        let cancel = CancellationToken::new();
        let mut bindings = SessionBindings::new();
        bindings
            .insert(session_id, SessionBinding::connecting(cancel.clone()))
            .unwrap();

        let handle = orch
            .connect(
                http_profile(),
                ConnectOptions {
                    cancel: cancel.clone(),
                    session_id: Some(session_id),
                    ..ConnectOptions::default()
                },
            )
            .await;
        assert_eq!(handle.id(), session_id);
        assert_eq!(handle.state(), SessionState::Connected);
        bindings.attach_handle(handle).await.unwrap();
        assert!(bindings.get(session_id).unwrap().is_connected());

        let mut bar = SessionTabBarState::new();
        open_tab_for_session(&mut bar, session_id, "http", ProtocolType::Http).unwrap();
        close_tab_and_dispose_session(&mut bar, &mut bindings, session_id)
            .await
            .unwrap();
        assert!(bindings.is_empty());
        assert!(bar.is_empty());
    }

    #[tokio::test]
    async fn attach_handle_unknown_disposes_orphan_lease() {
        let (manager, tunnel_id, handle, _cancel) = connect_ssh_with_tunnel().await;
        assert_eq!(handle.state(), SessionState::Connected);
        assert_eq!(manager.pool_ref_count(tunnel_id), 1);

        // Tab closed (or never registered) before attach — must not leak the lease.
        let mut bindings = SessionBindings::new();
        bindings.attach_handle(handle).await.unwrap();
        assert!(bindings.is_empty());
        assert_eq!(manager.pool_ref_count(tunnel_id), 0);
    }

    #[tokio::test]
    async fn attach_handle_already_connected_fail_closed() {
        let orch = orch_no_tunnel();
        let first = orch
            .connect(http_profile(), ConnectOptions::default())
            .await;
        let id = first.id();
        let cancel = CancellationToken::new();
        let mut bindings = SessionBindings::new();
        bindings
            .insert_connected(first, cancel.clone())
            .unwrap();

        let second = orch
            .connect(
                http_profile(),
                ConnectOptions {
                    session_id: Some(id),
                    ..ConnectOptions::default()
                },
            )
            .await;
        assert_eq!(second.id(), id);
        let err = bindings
            .attach_handle(second)
            .await
            .expect_err("second attach");
        assert_eq!(err, SessionTabGlueError::DuplicateBinding(id.as_uuid()));
        // Existing binding untouched.
        assert!(bindings.get(id).unwrap().is_connected());
        assert_eq!(bindings.len(), 1);

        let mut bar = SessionTabBarState::new();
        open_tab_for_session(&mut bar, id, "http", ProtocolType::Http).unwrap();
        close_tab_and_dispose_session(&mut bar, &mut bindings, id)
            .await
            .unwrap();
        assert!(bindings.is_empty());
    }

    #[tokio::test]
    async fn insert_connected_handle_id_mismatch_fail_closed() {
        let orch = orch_no_tunnel();
        let handle = orch
            .connect(http_profile(), ConnectOptions::default())
            .await;
        let wrong_id = fake_id();
        let mut bindings = SessionBindings::new();
        let err = bindings
            .insert(
                wrong_id,
                SessionBinding::connected(handle, CancellationToken::new()),
            )
            .unwrap_err();
        assert!(matches!(err, SessionTabGlueError::HandleIdMismatch { .. }));
        assert!(bindings.is_empty());
    }
}
