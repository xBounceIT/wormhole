//! Session open/close ↔ [`BrokerPaneLayoutSink`] bind/unbind glue (Fake broker).
//!
//! Enabled with `--features pane-layout`. Pure Rust stub: session open registers a
//! surface on the Fake / [`crate::StubNativeSurfaceBroker`] and binds it to a pane;
//! session close unbinds then unregisters (dispose). Unknown-surface dispose drops
//! the registry entry (retry no-op); other dispose errors keep it for retry.
//! No live HWND / WebView2 / GPUI. Does **not** rewrite
//! [`super::pane_layout::BrokerPaneLayoutSink`] layout ticks.

use std::collections::HashMap;

use wormhole_ui::{PaneId, SessionId};

use crate::broker::{OwnerHwnd, SurfaceHandle, SurfaceId};
use crate::kinds::SurfaceKind;
use crate::pane_layout::BrokerPaneLayoutSink;
use crate::{NativeSurfaceBroker, SurfaceError};

/// Alias for the in-memory Fake broker used by this glue (no HWND / COM).
pub type FakeNativeSurfaceBroker = crate::StubNativeSurfaceBroker;

/// One live session → pane + registered surface mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionSurfaceBinding {
    /// Pane the surface is bound to for layout ticks.
    pub pane: PaneId,
    /// Handle returned by Fake [`NativeSurfaceBroker::register`].
    pub handle: SurfaceHandle,
}

/// Tracks which sessions own which Fake surfaces (and panes).
#[derive(Debug, Default, Clone)]
pub struct SessionSurfaceRegistry {
    by_session: HashMap<SessionId, SessionSurfaceBinding>,
}

impl SessionSurfaceRegistry {
    /// Empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Binding for `session`, if tracked.
    pub fn get(&self, session: SessionId) -> Option<SessionSurfaceBinding> {
        self.by_session.get(&session).copied()
    }

    /// Number of tracked sessions.
    pub fn len(&self) -> usize {
        self.by_session.len()
    }

    /// True when no sessions are tracked.
    pub fn is_empty(&self) -> bool {
        self.by_session.is_empty()
    }

    /// Session currently owning `pane`, if any.
    pub fn session_for_pane(&self, pane: PaneId) -> Option<SessionId> {
        self.by_session
            .iter()
            .find(|(_, b)| b.pane == pane)
            .map(|(id, _)| *id)
    }
}

/// Errors from session ↔ surface glue (fail-closed; no partial open).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionSurfaceError {
    /// `session` already has a Fake surface binding.
    DuplicateSession(SessionId),
    /// `pane` is already owned by another tracked session.
    PaneInUse {
        /// Contested pane.
        pane: PaneId,
        /// Session that already owns the pane.
        session: SessionId,
    },
    /// Surface id was never registered (or already disposed).
    UnknownSurface(SurfaceId),
    /// Propagated broker / platform failure.
    Surface(SurfaceError),
}

impl std::fmt::Display for SessionSurfaceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DuplicateSession(id) => {
                write!(f, "session {id} already has a surface binding")
            }
            Self::PaneInUse { pane, session } => {
                write!(
                    f,
                    "pane {} is already bound to session {session}",
                    pane.0
                )
            }
            Self::UnknownSurface(id) => write!(f, "unknown surface id {id}"),
            Self::Surface(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for SessionSurfaceError {}

impl From<SurfaceError> for SessionSurfaceError {
    fn from(value: SurfaceError) -> Self {
        match value {
            SurfaceError::UnknownSurface(id) => Self::UnknownSurface(id),
            other => Self::Surface(other),
        }
    }
}

/// Open a session surface: Fake `register` + bind to `pane`.
///
/// - **Duplicate session** → [`SessionSurfaceError::DuplicateSession`] (unchanged).
/// - **Pane already owned** by another tracked session → [`SessionSurfaceError::PaneInUse`].
/// - Broker register failure → fail-closed (nothing tracked).
pub fn open_session_surface<B: NativeSurfaceBroker>(
    sink: &mut BrokerPaneLayoutSink<B>,
    registry: &mut SessionSurfaceRegistry,
    session: SessionId,
    pane: PaneId,
    owner: OwnerHwnd,
    kind: SurfaceKind,
) -> Result<SurfaceHandle, SessionSurfaceError> {
    if registry.by_session.contains_key(&session) {
        return Err(SessionSurfaceError::DuplicateSession(session));
    }
    if let Some(other) = registry.session_for_pane(pane) {
        return Err(SessionSurfaceError::PaneInUse {
            pane,
            session: other,
        });
    }

    let handle = sink.register_and_bind(pane, owner, kind)?;
    registry.by_session.insert(
        session,
        SessionSurfaceBinding { pane, handle },
    );
    Ok(handle)
}

/// Close a session surface: unbind (if still ours) + unregister (dispose Fake).
///
/// **Idempotent:** unknown / already-closed `session` → `Ok(())`.
///
/// If the surface id is missing from the broker at dispose time →
/// [`SessionSurfaceError::UnknownSurface`] (fail-closed). The session is then
/// dropped from the registry so a retry is a no-op.
///
/// Other broker dispose failures leave the registry entry intact so close can
/// be retried (pane may already be unbound; unregister is attempted again).
pub fn close_session_surface<B: NativeSurfaceBroker>(
    sink: &mut BrokerPaneLayoutSink<B>,
    registry: &mut SessionSurfaceRegistry,
    session: SessionId,
) -> Result<(), SessionSurfaceError> {
    let Some(binding) = registry.get(session) else {
        return Ok(());
    };

    // Only unbind if this session's handle is still the pane mapping (rebind-safe).
    if sink.binding(binding.pane).map(|h| h.id) == Some(binding.handle.id) {
        sink.unbind(binding.pane);
    }

    match sink.broker_mut().unregister(binding.handle.id) {
        Ok(()) => {
            registry.by_session.remove(&session);
            Ok(())
        }
        Err(SurfaceError::UnknownSurface(id)) => {
            registry.by_session.remove(&session);
            Err(SessionSurfaceError::UnknownSurface(id))
        }
        Err(err) => Err(SessionSurfaceError::Surface(err)),
    }
}

/// Look up a tracked binding; unknown session is not an error (returns `None`).
pub fn session_surface(
    registry: &SessionSurfaceRegistry,
    session: SessionId,
) -> Option<SessionSurfaceBinding> {
    registry.get(session)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bounds::{PhysicalBounds, SurfaceVisibility, ZOrderHint};
    use crate::broker::SurfaceLayoutUpdate;
    use wormhole_ui::{PaneLayoutSink, PaneLayoutUpdate, PanePhysicalBounds};

    fn fake_session() -> SessionId {
        SessionId::new()
    }

    fn pane_update(pane: u8, w: u32, h: u32) -> PaneLayoutUpdate {
        PaneLayoutUpdate {
            pane: PaneId(pane),
            bounds: PanePhysicalBounds {
                x: 0,
                y: 0,
                width: w,
                height: h,
                dpi: 96,
            },
        }
    }

    #[test]
    fn open_binds_surface_to_pane_and_layout_reaches_fake() {
        let mut sink = BrokerPaneLayoutSink::new(FakeNativeSurfaceBroker::new());
        let mut registry = SessionSurfaceRegistry::new();
        let session = fake_session();

        let handle = open_session_surface(
            &mut sink,
            &mut registry,
            session,
            PaneId(0),
            OwnerHwnd(0x1000),
            SurfaceKind::WebView2,
        )
        .expect("open");

        assert_eq!(handle.kind, SurfaceKind::WebView2);
        assert_eq!(sink.binding(PaneId(0)).map(|h| h.id), Some(handle.id));
        assert_eq!(
            registry.get(session),
            Some(SessionSurfaceBinding {
                pane: PaneId(0),
                handle,
            })
        );

        sink.on_pane_layout(&[pane_update(0, 800, 600)]);
        let u = sink.broker().last_update(handle.id).expect("layout");
        assert_eq!(u.visibility, SurfaceVisibility::Visible);
        assert_eq!(u.bounds.width, 800);
    }

    #[test]
    fn open_rdp_kind_registers_without_com() {
        let mut sink = BrokerPaneLayoutSink::new(FakeNativeSurfaceBroker::new());
        let mut registry = SessionSurfaceRegistry::new();
        let handle = open_session_surface(
            &mut sink,
            &mut registry,
            fake_session(),
            PaneId(1),
            OwnerHwnd(1),
            SurfaceKind::RdpActiveX,
        )
        .expect("rdp open");
        assert_eq!(handle.kind, SurfaceKind::RdpActiveX);
        assert_eq!(sink.broker().list().len(), 1);
    }

    #[test]
    fn duplicate_session_fail_closed() {
        let mut sink = BrokerPaneLayoutSink::new(FakeNativeSurfaceBroker::new());
        let mut registry = SessionSurfaceRegistry::new();
        let session = fake_session();
        open_session_surface(
            &mut sink,
            &mut registry,
            session,
            PaneId(0),
            OwnerHwnd(1),
            SurfaceKind::WebView2,
        )
        .unwrap();
        let before = registry.clone();
        let list_before = sink.broker().list().len();

        assert_eq!(
            open_session_surface(
                &mut sink,
                &mut registry,
                session,
                PaneId(1),
                OwnerHwnd(1),
                SurfaceKind::RdpActiveX,
            ),
            Err(SessionSurfaceError::DuplicateSession(session))
        );
        assert_eq!(registry.by_session, before.by_session);
        assert_eq!(sink.broker().list().len(), list_before);
        assert_eq!(sink.binding(PaneId(1)), None);
    }

    #[test]
    fn pane_in_use_fail_closed() {
        let mut sink = BrokerPaneLayoutSink::new(FakeNativeSurfaceBroker::new());
        let mut registry = SessionSurfaceRegistry::new();
        let a = fake_session();
        let b = fake_session();
        open_session_surface(
            &mut sink,
            &mut registry,
            a,
            PaneId(0),
            OwnerHwnd(1),
            SurfaceKind::WebView2,
        )
        .unwrap();

        assert_eq!(
            open_session_surface(
                &mut sink,
                &mut registry,
                b,
                PaneId(0),
                OwnerHwnd(1),
                SurfaceKind::RdpActiveX,
            ),
            Err(SessionSurfaceError::PaneInUse {
                pane: PaneId(0),
                session: a,
            })
        );
        assert!(registry.get(b).is_none());
        assert_eq!(sink.broker().list().len(), 1);
    }

    #[test]
    fn close_unbinds_and_disposes_fake() {
        let mut sink = BrokerPaneLayoutSink::new(FakeNativeSurfaceBroker::new());
        let mut registry = SessionSurfaceRegistry::new();
        let session = fake_session();
        let handle = open_session_surface(
            &mut sink,
            &mut registry,
            session,
            PaneId(0),
            OwnerHwnd(1),
            SurfaceKind::WebView2,
        )
        .unwrap();
        sink.on_pane_layout(&[pane_update(0, 10, 10)]);

        close_session_surface(&mut sink, &mut registry, session).expect("close");

        assert!(registry.is_empty());
        assert!(sink.binding(PaneId(0)).is_none());
        assert!(sink.broker().list().is_empty());
        // Dispose = unregister: further bounds updates fail-closed at broker.
        assert_eq!(
            sink.broker_mut().update_bounds(
                handle.id,
                SurfaceLayoutUpdate {
                    bounds: PhysicalBounds::SEED,
                    visibility: SurfaceVisibility::Hidden,
                    z_order: ZOrderHint::Unchanged,
                },
            ),
            Err(SurfaceError::UnknownSurface(handle.id))
        );
    }

    #[test]
    fn close_is_idempotent() {
        let mut sink = BrokerPaneLayoutSink::new(FakeNativeSurfaceBroker::new());
        let mut registry = SessionSurfaceRegistry::new();
        let session = fake_session();
        open_session_surface(
            &mut sink,
            &mut registry,
            session,
            PaneId(0),
            OwnerHwnd(1),
            SurfaceKind::WebView2,
        )
        .unwrap();

        close_session_surface(&mut sink, &mut registry, session).unwrap();
        close_session_surface(&mut sink, &mut registry, session).unwrap();
        close_session_surface(&mut sink, &mut registry, fake_session()).unwrap();
        assert!(registry.is_empty());
        assert!(sink.broker().list().is_empty());
    }

    #[test]
    fn unknown_surface_on_dispose_fail_closed() {
        let mut sink = BrokerPaneLayoutSink::new(FakeNativeSurfaceBroker::new());
        let mut registry = SessionSurfaceRegistry::new();
        let session = fake_session();
        let handle = open_session_surface(
            &mut sink,
            &mut registry,
            session,
            PaneId(0),
            OwnerHwnd(1),
            SurfaceKind::WebView2,
        )
        .unwrap();

        // External dispose leaves registry stale until close.
        sink.broker_mut().unregister(handle.id).expect("gone");
        assert_eq!(
            close_session_surface(&mut sink, &mut registry, session),
            Err(SessionSurfaceError::UnknownSurface(handle.id))
        );
        // Session dropped so retry is idempotent Ok.
        assert!(registry.get(session).is_none());
        close_session_surface(&mut sink, &mut registry, session).unwrap();
    }

    #[test]
    fn close_does_not_unbind_out_of_band_rebind() {
        let mut sink = BrokerPaneLayoutSink::new(FakeNativeSurfaceBroker::new());
        let mut registry = SessionSurfaceRegistry::new();
        let a = fake_session();
        let handle_a = open_session_surface(
            &mut sink,
            &mut registry,
            a,
            PaneId(0),
            OwnerHwnd(1),
            SurfaceKind::WebView2,
        )
        .unwrap();

        // Out-of-band rebind (glue open path normally refuses PaneInUse).
        let handle_b = sink
            .broker_mut()
            .register(OwnerHwnd(1), SurfaceKind::RdpActiveX)
            .unwrap();
        sink.bind(PaneId(0), handle_b);

        close_session_surface(&mut sink, &mut registry, a).unwrap();
        // B's binding must remain; only A's Fake disposed.
        assert_eq!(sink.binding(PaneId(0)).map(|h| h.id), Some(handle_b.id));
        assert!(sink.broker().list().iter().all(|h| h.id != handle_a.id));
        assert!(sink.broker().list().iter().any(|h| h.id == handle_b.id));
    }

    #[test]
    fn reopen_after_close_gets_fresh_surface_id() {
        let mut sink = BrokerPaneLayoutSink::new(FakeNativeSurfaceBroker::new());
        let mut registry = SessionSurfaceRegistry::new();
        let session = fake_session();
        let first = open_session_surface(
            &mut sink,
            &mut registry,
            session,
            PaneId(0),
            OwnerHwnd(1),
            SurfaceKind::WebView2,
        )
        .unwrap();
        close_session_surface(&mut sink, &mut registry, session).unwrap();
        let second = open_session_surface(
            &mut sink,
            &mut registry,
            session,
            PaneId(0),
            OwnerHwnd(1),
            SurfaceKind::WebView2,
        )
        .unwrap();
        assert_ne!(first.id, second.id);
        assert_eq!(sink.binding(PaneId(0)).map(|h| h.id), Some(second.id));
    }

    #[test]
    fn session_surface_lookup_and_session_for_pane() {
        let mut sink = BrokerPaneLayoutSink::new(FakeNativeSurfaceBroker::new());
        let mut registry = SessionSurfaceRegistry::new();
        let session = fake_session();
        assert!(session_surface(&registry, session).is_none());
        let handle = open_session_surface(
            &mut sink,
            &mut registry,
            session,
            PaneId(2),
            OwnerHwnd(1),
            SurfaceKind::WebView2,
        )
        .unwrap();
        assert_eq!(
            session_surface(&registry, session),
            Some(SessionSurfaceBinding {
                pane: PaneId(2),
                handle,
            })
        );
        assert_eq!(registry.session_for_pane(PaneId(2)), Some(session));
        assert!(registry.session_for_pane(PaneId(0)).is_none());
    }

    #[test]
    fn close_after_external_unbind_still_disposes() {
        let mut sink = BrokerPaneLayoutSink::new(FakeNativeSurfaceBroker::new());
        let mut registry = SessionSurfaceRegistry::new();
        let session = fake_session();
        let handle = open_session_surface(
            &mut sink,
            &mut registry,
            session,
            PaneId(0),
            OwnerHwnd(1),
            SurfaceKind::WebView2,
        )
        .unwrap();
        sink.unbind(PaneId(0));
        assert!(sink.binding(PaneId(0)).is_none());
        assert_eq!(sink.broker().list().len(), 1);

        close_session_surface(&mut sink, &mut registry, session).unwrap();
        assert!(registry.is_empty());
        assert!(sink.broker().list().is_empty());
        assert_eq!(
            sink.broker_mut().update_bounds(
                handle.id,
                SurfaceLayoutUpdate {
                    bounds: PhysicalBounds::SEED,
                    visibility: SurfaceVisibility::Hidden,
                    z_order: ZOrderHint::Unchanged,
                },
            ),
            Err(SurfaceError::UnknownSurface(handle.id))
        );
    }

    #[test]
    fn close_without_layout_still_unbinds_and_disposes() {
        let mut sink = BrokerPaneLayoutSink::new(FakeNativeSurfaceBroker::new());
        let mut registry = SessionSurfaceRegistry::new();
        let session = fake_session();
        open_session_surface(
            &mut sink,
            &mut registry,
            session,
            PaneId(0),
            OwnerHwnd(1),
            SurfaceKind::WebView2,
        )
        .unwrap();
        close_session_surface(&mut sink, &mut registry, session).unwrap();
        assert!(registry.is_empty());
        assert!(sink.binding(PaneId(0)).is_none());
        assert!(sink.broker().list().is_empty());
    }

    /// Scripted Fake: register/unregister can fail without touching HWND/COM.
    #[derive(Debug)]
    struct ScriptedBroker {
        inner: FakeNativeSurfaceBroker,
        fail_register: bool,
        fail_unregister_with: Option<SurfaceError>,
        unregister_calls: usize,
    }

    impl ScriptedBroker {
        fn new() -> Self {
            Self {
                inner: FakeNativeSurfaceBroker::new(),
                fail_register: false,
                fail_unregister_with: None,
                unregister_calls: 0,
            }
        }
    }

    impl NativeSurfaceBroker for ScriptedBroker {
        fn register(&mut self, owner: OwnerHwnd, kind: SurfaceKind) -> crate::Result<SurfaceHandle> {
            if self.fail_register {
                return Err(SurfaceError::NotImplemented("scripted register fail"));
            }
            self.inner.register(owner, kind)
        }

        fn update_bounds(
            &mut self,
            id: SurfaceId,
            update: SurfaceLayoutUpdate,
        ) -> crate::Result<()> {
            self.inner.update_bounds(id, update)
        }

        fn unregister(&mut self, id: SurfaceId) -> crate::Result<()> {
            self.unregister_calls += 1;
            if let Some(err) = self.fail_unregister_with.clone() {
                return Err(err);
            }
            self.inner.unregister(id)
        }

        fn list(&self) -> Vec<SurfaceHandle> {
            self.inner.list()
        }
    }

    #[test]
    fn open_register_failure_fail_closed() {
        let mut broker = ScriptedBroker::new();
        broker.fail_register = true;
        let mut sink = BrokerPaneLayoutSink::new(broker);
        let mut registry = SessionSurfaceRegistry::new();
        let session = fake_session();

        assert_eq!(
            open_session_surface(
                &mut sink,
                &mut registry,
                session,
                PaneId(0),
                OwnerHwnd(1),
                SurfaceKind::WebView2,
            ),
            Err(SessionSurfaceError::Surface(SurfaceError::NotImplemented(
                "scripted register fail"
            )))
        );
        assert!(registry.is_empty());
        assert!(sink.binding(PaneId(0)).is_none());
        assert!(sink.broker().list().is_empty());
    }

    #[test]
    fn close_retryable_surface_error_keeps_registry_then_succeeds() {
        let broker = ScriptedBroker::new();
        let mut sink = BrokerPaneLayoutSink::new(broker);
        let mut registry = SessionSurfaceRegistry::new();
        let session = fake_session();
        let handle = open_session_surface(
            &mut sink,
            &mut registry,
            session,
            PaneId(0),
            OwnerHwnd(1),
            SurfaceKind::WebView2,
        )
        .unwrap();

        sink.broker_mut().fail_unregister_with =
            Some(SurfaceError::NotImplemented("scripted unregister fail"));
        assert_eq!(
            close_session_surface(&mut sink, &mut registry, session),
            Err(SessionSurfaceError::Surface(SurfaceError::NotImplemented(
                "scripted unregister fail"
            )))
        );
        // Registry kept so retry can dispose; pane already unbound.
        assert_eq!(
            registry.get(session).map(|b| b.handle.id),
            Some(handle.id)
        );
        assert!(sink.binding(PaneId(0)).is_none());
        assert_eq!(sink.broker().unregister_calls, 1);
        // Surface still live under the scripted failure (inner never reached).
        assert_eq!(sink.broker().list().len(), 1);
        // Pane still considered owned → new open fail-closed.
        assert_eq!(
            open_session_surface(
                &mut sink,
                &mut registry,
                fake_session(),
                PaneId(0),
                OwnerHwnd(1),
                SurfaceKind::RdpActiveX,
            ),
            Err(SessionSurfaceError::PaneInUse {
                pane: PaneId(0),
                session,
            })
        );

        sink.broker_mut().fail_unregister_with = None;
        close_session_surface(&mut sink, &mut registry, session).unwrap();
        assert!(registry.is_empty());
        assert!(sink.broker().list().is_empty());
        assert_eq!(sink.broker().unregister_calls, 2);
    }
}
