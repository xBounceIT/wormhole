//! VNC framebuffer / input ↔ session glue stub.
//!
//! Thin Lab stub: wires existing [`VncSession`] + [`InputEventQueue`] +
//! [`RawPixelBuffer`] damage into a host dirty-notify sink. Pointer/key
//! events enqueue on the session input queue; Raw framebuffer rects apply
//! through the decode stub then notify [`FramebufferDirtyNotify`].
//!
//! **No live RFB / TCP.** Unit tests use [`FakeFramebufferDirtyNotify`].
//! The session orchestrator still fails closed with `UnsupportedProtocol`
//! before tunnel establish — this glue is for surface hosts that already
//! hold a [`VncSession`] stub after [`VncSession::mark_connected`].
//!
//! Fail-closed when the session is not [`VncSessionState::Connected`]
//! (`VncError::NotConnected`); full input queue still yields
//! [`VncError::InputQueueFull`] (queue unchanged). Apply errors skip
//! dirty notify (no partial invalidate).

use std::fmt;

use crate::framebuffer::{DamageRect, FramebufferRect};
use crate::input::{KeyEvent, PointerEvent, VncInputSink};
use crate::session::{VncConnectOptions, VncSession, VncSessionState};
use crate::VncError;

/// Host callback when the framebuffer gains damage that needs a redraw.
///
/// Production will map this to a GPUI / WinUI invalidate; Lab uses
/// [`FakeFramebufferDirtyNotify`]. Empty `rects` must be a no-op for callers
/// that still invoke the trait (this glue skips empty before notify).
pub trait FramebufferDirtyNotify: Send {
    fn on_framebuffer_dirty(&mut self, rects: &[DamageRect]);
}

/// Records dirty notifications for tests / Lab harnesses (no GPUI blit).
#[derive(Clone, Default)]
pub struct FakeFramebufferDirtyNotify {
    notifications: Vec<Vec<DamageRect>>,
}

impl FakeFramebufferDirtyNotify {
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of non-empty dirty notify calls.
    pub fn len(&self) -> usize {
        self.notifications.len()
    }

    pub fn is_empty(&self) -> bool {
        self.notifications.is_empty()
    }

    /// All recorded notify batches (each batch is the damage taken after one rect).
    pub fn notifications(&self) -> &[Vec<DamageRect>] {
        &self.notifications
    }

    /// Flattened damage rects across all notifies (order preserved).
    pub fn all_rects(&self) -> Vec<DamageRect> {
        self.notifications.iter().flatten().copied().collect()
    }

    pub fn clear(&mut self) {
        self.notifications.clear();
    }
}

impl fmt::Debug for FakeFramebufferDirtyNotify {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FakeFramebufferDirtyNotify")
            .field("notifications", &self.notifications.len())
            .field(
                "total_rects",
                &self.notifications.iter().map(|b| b.len()).sum::<usize>(),
            )
            .finish()
    }
}

impl FramebufferDirtyNotify for FakeFramebufferDirtyNotify {
    fn on_framebuffer_dirty(&mut self, rects: &[DamageRect]) {
        if rects.is_empty() {
            return;
        }
        self.notifications.push(rects.to_vec());
    }
}

/// No-op dirty notify (production host not wired yet).
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopFramebufferDirtyNotify;

impl FramebufferDirtyNotify for NoopFramebufferDirtyNotify {
    fn on_framebuffer_dirty(&mut self, _rects: &[DamageRect]) {}
}

/// Owns a [`VncSession`] stub + dirty-notify sink.
///
/// Pointer/key → [`VncInputSink`] / input queue; Raw FB rect →
/// [`VncSession::push_rect`] then [`FramebufferDirtyNotify`].
pub struct VncSessionGlue<N: FramebufferDirtyNotify> {
    session: VncSession,
    dirty: N,
}

impl<N: FramebufferDirtyNotify + fmt::Debug> fmt::Debug for VncSessionGlue<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Delegate to session Debug (redacts password; summarizes FB/input).
        f.debug_struct("VncSessionGlue")
            .field("session", &self.session)
            .field("dirty", &self.dirty)
            .finish()
    }
}

impl<N: FramebufferDirtyNotify> VncSessionGlue<N> {
    pub fn new(session: VncSession, dirty: N) -> Self {
        Self { session, dirty }
    }

    pub fn session(&self) -> &VncSession {
        &self.session
    }

    pub fn session_mut(&mut self) -> &mut VncSession {
        &mut self.session
    }

    pub fn dirty_notify(&self) -> &N {
        &self.dirty
    }

    pub fn dirty_notify_mut(&mut self) -> &mut N {
        &mut self.dirty
    }

    pub fn into_parts(self) -> (VncSession, N) {
        (self.session, self.dirty)
    }

    pub fn is_connected(&self) -> bool {
        self.session.state == VncSessionState::Connected
    }

    pub fn mark_connected(&mut self, width: u16, height: u16) {
        self.session.mark_connected(width, height);
    }

    pub fn close(&mut self) {
        self.session.close();
    }

    /// Enqueue a pointer event on the session input queue.
    ///
    /// Fail-closed when not connected ([`VncError::NotConnected`]).
    pub fn push_pointer(&mut self, event: PointerEvent) -> Result<(), VncError> {
        push_pointer_to_session(&mut self.session, event)
    }

    /// Enqueue a key event on the session input queue.
    ///
    /// Fail-closed when not connected ([`VncError::NotConnected`]).
    pub fn push_key(&mut self, event: KeyEvent) -> Result<(), VncError> {
        push_key_to_session(&mut self.session, event)
    }

    /// Apply a Raw framebuffer rect, then notify dirty with taken damage.
    ///
    /// Fail-closed when not connected. On apply error, the dirty notify is
    /// **not** invoked (no partial invalidate). Empty damage after a successful
    /// zero-size rect is skipped (no notify call).
    pub fn push_framebuffer_rect(&mut self, rect: FramebufferRect) -> Result<(), VncError> {
        apply_framebuffer_rect(&mut self.session, &mut self.dirty, rect)
    }
}

impl VncSessionGlue<FakeFramebufferDirtyNotify> {
    /// Lab / unit path: new session + recording dirty notify.
    pub fn with_fake(options: VncConnectOptions) -> Self {
        Self::new(VncSession::new(options), FakeFramebufferDirtyNotify::new())
    }

    /// Same as [`Self::with_fake`] with an explicit input-queue capacity.
    pub fn with_fake_input_capacity(options: VncConnectOptions, capacity: usize) -> Self {
        Self::new(
            VncSession::with_input_capacity(options, capacity),
            FakeFramebufferDirtyNotify::new(),
        )
    }
}

/// Enqueue pointer → session input queue (fail-closed unless Connected).
pub fn push_pointer_to_session(
    session: &mut VncSession,
    event: PointerEvent,
) -> Result<(), VncError> {
    session.pointer(event)
}

/// Enqueue key → session input queue (fail-closed unless Connected).
pub fn push_key_to_session(session: &mut VncSession, event: KeyEvent) -> Result<(), VncError> {
    session.key(event)
}

/// Apply Raw FB rect on `session`, then notify `dirty` with taken damage.
///
/// | Session state | Behaviour |
/// |---|---|
/// | not Connected | [`VncError::NotConnected`] — no blit, no notify |
/// | Connected + apply ok | take damage; notify only when non-empty |
/// | Connected + apply err | error returned; notify **not** called |
pub fn apply_framebuffer_rect(
    session: &mut VncSession,
    dirty: &mut dyn FramebufferDirtyNotify,
    rect: FramebufferRect,
) -> Result<(), VncError> {
    session.push_rect(rect)?;
    let damage = session.framebuffer.take_damage();
    if !damage.is_empty() {
        dirty.on_framebuffer_dirty(&damage);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::input::{InputEvent, PointerButtons};
    use bytes::Bytes;
    use std::net::{Ipv4Addr, SocketAddr};

    fn addr() -> SocketAddr {
        SocketAddr::from((Ipv4Addr::LOCALHOST, 5900))
    }

    fn opts() -> VncConnectOptions {
        VncConnectOptions::new(addr())
    }

    fn one_pixel_rect(x: u16, y: u16) -> FramebufferRect {
        FramebufferRect {
            x,
            y,
            width: 1,
            height: 1,
            pixels: Bytes::from_static(&[0, 0, 255, 255]),
        }
    }

    /// OOB 2×1 at (3,3) on a 4×4 buffer (8 bytes = correct length for the rect).
    fn oob_rect() -> FramebufferRect {
        FramebufferRect {
            x: 3,
            y: 3,
            width: 2,
            height: 1,
            pixels: Bytes::from(vec![0u8; 8]),
        }
    }

    fn empty_pointer() -> PointerEvent {
        PointerEvent {
            x: 0,
            y: 0,
            buttons: PointerButtons::empty(),
        }
    }

    /// Counts every dirty invoke (including empty) — unlike Fake, which filters.
    #[derive(Default)]
    struct CountingDirtyNotify {
        calls: usize,
        empty_calls: usize,
    }

    impl FramebufferDirtyNotify for CountingDirtyNotify {
        fn on_framebuffer_dirty(&mut self, rects: &[DamageRect]) {
            self.calls += 1;
            if rects.is_empty() {
                self.empty_calls += 1;
            }
        }
    }

    #[test]
    fn pointer_and_key_enqueue_when_connected() {
        let mut glue = VncSessionGlue::with_fake(opts());
        glue.mark_connected(64, 48);
        glue
            .push_pointer(PointerEvent {
                x: 10,
                y: 20,
                buttons: PointerButtons::LEFT,
            })
            .unwrap();
        glue
            .push_key(KeyEvent {
                keysym: 0x61,
                down: true,
            })
            .unwrap();
        assert_eq!(glue.session().input.len(), 2);
        assert!(glue.dirty_notify().is_empty());
    }

    #[test]
    fn input_fail_closed_when_not_connected() {
        let mut glue = VncSessionGlue::with_fake(opts());
        assert!(!glue.is_connected());
        assert_eq!(glue.push_pointer(empty_pointer()), Err(VncError::NotConnected));
        assert_eq!(
            glue.push_key(KeyEvent {
                keysym: 1,
                down: false,
            }),
            Err(VncError::NotConnected)
        );
        assert_eq!(glue.session().input.len(), 0);

        // Negotiating is also not Connected — fail closed via real negotiate path.
        glue
            .session_mut()
            .negotiate_security(&[1])
            .expect("None security accepted");
        assert_eq!(glue.session().state, VncSessionState::Negotiating);
        assert_eq!(glue.push_pointer(empty_pointer()), Err(VncError::NotConnected));
    }

    #[test]
    fn input_and_framebuffer_fail_closed_after_close() {
        let mut glue = VncSessionGlue::with_fake(opts());
        glue.mark_connected(8, 8);
        glue
            .push_pointer(PointerEvent {
                x: 1,
                y: 1,
                buttons: PointerButtons::LEFT,
            })
            .unwrap();
        glue
            .push_key(KeyEvent {
                keysym: 0x61,
                down: true,
            })
            .unwrap();
        assert_eq!(glue.session().input.len(), 2);

        glue.close();
        assert!(!glue.is_connected());
        assert_eq!(glue.session().state, VncSessionState::Closed);
        // close() clears the input queue — no stale events after teardown.
        assert_eq!(glue.session().input.len(), 0);

        assert_eq!(
            glue.push_pointer(PointerEvent {
                x: 2,
                y: 2,
                buttons: PointerButtons::empty(),
            }),
            Err(VncError::NotConnected)
        );
        assert_eq!(
            glue.push_key(KeyEvent {
                keysym: 2,
                down: false,
            }),
            Err(VncError::NotConnected)
        );
        assert_eq!(glue.session().input.len(), 0);

        assert_eq!(
            glue.push_framebuffer_rect(one_pixel_rect(0, 0)),
            Err(VncError::NotConnected)
        );
        assert!(glue.dirty_notify().is_empty());
    }

    #[test]
    fn framebuffer_rect_notifies_fake_dirty() {
        let mut glue = VncSessionGlue::with_fake(opts());
        glue.mark_connected(16, 16);
        glue.push_framebuffer_rect(one_pixel_rect(2, 3)).unwrap();
        assert_eq!(glue.dirty_notify().len(), 1);
        assert_eq!(
            glue.dirty_notify().all_rects(),
            vec![DamageRect::new(2, 3, 1, 1)]
        );
        // Damage was taken for notify — session buffer damage cleared.
        assert!(glue.session().framebuffer.damage().is_empty());
        // Pixel store still has the blit.
        assert_eq!(glue.session().framebuffer.width(), 16);
    }

    #[test]
    fn framebuffer_fail_closed_when_not_connected_no_notify() {
        let mut glue = VncSessionGlue::with_fake(opts());
        assert_eq!(
            glue.push_framebuffer_rect(one_pixel_rect(0, 0)),
            Err(VncError::NotConnected)
        );
        assert!(glue.dirty_notify().is_empty());
    }

    #[test]
    fn invalid_framebuffer_update_skips_dirty_notify() {
        let mut glue = VncSessionGlue::with_fake(opts());
        glue.mark_connected(4, 4);
        // Establish a prior successful dirty notify so a later apply error must
        // not append another batch (dirty-after-error attack).
        glue.push_framebuffer_rect(one_pixel_rect(0, 0)).unwrap();
        assert_eq!(glue.dirty_notify().len(), 1);
        let pixels_before = glue.session().framebuffer.pixels().to_vec();

        // OOB rect → InvalidFramebufferUpdate; notify must not fire again.
        assert_eq!(
            glue.push_framebuffer_rect(oob_rect()),
            Err(VncError::InvalidFramebufferUpdate)
        );
        assert_eq!(glue.dirty_notify().len(), 1);
        assert!(glue.session().framebuffer.damage().is_empty());
        assert_eq!(glue.session().framebuffer.pixels(), pixels_before.as_slice());

        // Wrong pixel length is also InvalidFramebufferUpdate — still no notify.
        let wrong_len = FramebufferRect {
            x: 0,
            y: 0,
            width: 1,
            height: 1,
            pixels: Bytes::from_static(&[0, 0, 0]), // 3 bytes, need 4
        };
        assert_eq!(
            glue.push_framebuffer_rect(wrong_len),
            Err(VncError::InvalidFramebufferUpdate)
        );
        assert_eq!(glue.dirty_notify().len(), 1);

        // Recovery: a later valid rect still notifies.
        glue.push_framebuffer_rect(one_pixel_rect(1, 1)).unwrap();
        assert_eq!(glue.dirty_notify().len(), 2);
        assert_eq!(
            glue.dirty_notify().notifications()[1],
            vec![DamageRect::new(1, 1, 1, 1)]
        );
    }

    #[test]
    fn free_functions_wire_session_and_fake() {
        let mut session = VncSession::new(opts());
        session.mark_connected(8, 8);
        let mut dirty = FakeFramebufferDirtyNotify::new();

        push_pointer_to_session(
            &mut session,
            PointerEvent {
                x: 1,
                y: 2,
                buttons: PointerButtons::empty(),
            },
        )
        .unwrap();
        apply_framebuffer_rect(&mut session, &mut dirty, one_pixel_rect(0, 0)).unwrap();
        assert_eq!(session.input.len(), 1);
        assert_eq!(dirty.len(), 1);
        assert_eq!(dirty.all_rects(), vec![DamageRect::new(0, 0, 1, 1)]);
    }

    #[test]
    fn free_functions_fail_closed_and_skip_dirty_on_apply_err() {
        let mut session = VncSession::new(opts());
        let mut dirty = FakeFramebufferDirtyNotify::new();

        assert_eq!(
            push_pointer_to_session(&mut session, empty_pointer()),
            Err(VncError::NotConnected)
        );
        assert_eq!(
            push_key_to_session(
                &mut session,
                KeyEvent {
                    keysym: 1,
                    down: true,
                },
            ),
            Err(VncError::NotConnected)
        );
        assert_eq!(
            apply_framebuffer_rect(&mut session, &mut dirty, one_pixel_rect(0, 0)),
            Err(VncError::NotConnected)
        );
        assert!(dirty.is_empty());

        session.mark_connected(4, 4);
        apply_framebuffer_rect(&mut session, &mut dirty, one_pixel_rect(0, 0)).unwrap();
        assert_eq!(dirty.len(), 1);

        assert_eq!(
            apply_framebuffer_rect(&mut session, &mut dirty, oob_rect()),
            Err(VncError::InvalidFramebufferUpdate)
        );
        assert_eq!(dirty.len(), 1);
    }

    #[test]
    fn input_queue_full_propagates_no_silent_drop() {
        let mut glue = VncSessionGlue::with_fake_input_capacity(opts(), 1);
        glue.mark_connected(4, 4);
        let first = PointerEvent {
            x: 0,
            y: 0,
            buttons: PointerButtons::LEFT,
        };
        glue.push_pointer(first).unwrap();

        // Key when full — queue unchanged (first pointer retained).
        assert_eq!(
            glue.push_key(KeyEvent {
                keysym: 9,
                down: true,
            }),
            Err(VncError::InputQueueFull { capacity: 1 })
        );
        assert_eq!(glue.session().input.len(), 1);
        assert_eq!(
            glue.session_mut().input.dequeue(),
            Some(InputEvent::Pointer(first))
        );

        // Refill; pointer when full must also fail closed without drop.
        glue
            .push_key(KeyEvent {
                keysym: 9,
                down: true,
            })
            .unwrap();
        assert_eq!(
            glue.push_pointer(PointerEvent {
                x: 3,
                y: 4,
                buttons: PointerButtons::empty(),
            }),
            Err(VncError::InputQueueFull { capacity: 1 })
        );
        assert_eq!(glue.session().input.len(), 1);
        assert_eq!(
            glue.session_mut().input.dequeue(),
            Some(InputEvent::Key(KeyEvent {
                keysym: 9,
                down: true,
            }))
        );
    }

    #[test]
    fn zero_size_rect_ok_without_notify() {
        let mut glue = VncSessionGlue::with_fake(opts());
        glue.mark_connected(4, 4);
        glue
            .push_framebuffer_rect(FramebufferRect {
                x: 0,
                y: 0,
                width: 0,
                height: 1,
                pixels: Bytes::new(),
            })
            .unwrap();
        assert!(glue.dirty_notify().is_empty());
    }

    #[test]
    fn zero_size_rect_does_not_invoke_dirty_trait() {
        // Fake filters empty batches, so use a counting sink to prove the glue
        // itself skips the trait call when damage is empty.
        let mut glue = VncSessionGlue::new(VncSession::new(opts()), CountingDirtyNotify::default());
        glue.mark_connected(4, 4);
        glue
            .push_framebuffer_rect(FramebufferRect {
                x: 0,
                y: 0,
                width: 0,
                height: 1,
                pixels: Bytes::new(),
            })
            .unwrap();
        assert_eq!(glue.dirty_notify().calls, 0);
        assert_eq!(glue.dirty_notify().empty_calls, 0);
    }

    #[test]
    fn glue_and_fake_debug_omit_pixels_and_password() {
        use crate::auth::VncPassword;
        let mut glue = VncSessionGlue::with_fake(
            opts().with_password(VncPassword::new("sekrit!!").unwrap()),
        );
        glue.mark_connected(8, 8);
        glue.push_framebuffer_rect(one_pixel_rect(0, 0)).unwrap();
        let dbg = format!("{glue:?}");
        assert!(dbg.contains("VncSessionGlue"));
        assert!(dbg.contains("VncPassword(***)"));
        assert!(!dbg.contains("sekrit"));
        assert!(!dbg.contains("pixels:"));
        let fake_dbg = format!("{:?}", glue.dirty_notify());
        assert!(fake_dbg.contains("FakeFramebufferDirtyNotify"));
        assert!(fake_dbg.contains("notifications"));
    }

    #[test]
    fn into_parts_round_trips() {
        let mut glue = VncSessionGlue::with_fake(opts());
        glue.mark_connected(2, 2);
        glue.push_framebuffer_rect(one_pixel_rect(0, 0)).unwrap();
        let (session, dirty) = glue.into_parts();
        assert_eq!(session.state, VncSessionState::Connected);
        assert_eq!(dirty.len(), 1);
    }
}
