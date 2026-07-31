//! Input queue drain / coalesce on framebuffer resize + disconnect (Fake; no live RFB).
//!
//! Thin Lab stub: when the remote framebuffer size changes or the session
//! disconnects, pending pointer/key events in [`InputEventQueue`] are drained
//! and either re-shaped under the documented coalesce policy or discarded
//! fail-closed. No live TCP / `vnc-rs` send.
//!
//! # Coalesce policy
//!
//! ## Framebuffer resize ([`drain_coalesce_on_resize`])
//!
//! 1. **Drain** the entire pending queue (atomic take — queue empty on entry to
//!    reshape).
//! 2. **Drop** pointer events whose `(x, y)` fall outside the new size
//!    (`x >= width` or `y >= height`, or either axis is `0`). Fail-closed for
//!    OOB — never clamp into the new plane (same posture as Raw blit OOB reject).
//! 3. **Coalesce** consecutive pointer events that share the same button mask
//!    into the **last** one (classic move coalesce; intermediate moves are
//!    redundant for RFB PointerEvent).
//! 4. **Preserve** key events in FIFO order. Key down/up pairs cannot be
//!    coalesced without breaking server key state; keys are never dropped for
//!    being "out of bounds".
//! 5. **Re-enqueue** kept events. Coalesce only shrinks, so capacity cannot be
//!    exceeded after a full drain; if a hostile capacity somehow rejects,
//!    remaining kept events are discarded and [`VncError::InputQueueFull`] is
//!    returned (fail-closed — no silent partial keep without an error).
//!
//! Same-size resize still drains + coalesces (idempotent quiet path). A `0×0`
//! framebuffer drops every pointer (all OOB) and keeps keys.
//!
//! ## Disconnect ([`drain_discard_on_disconnect`])
//!
//! Drain and **discard** all pending events (fail-closed — never send after
//! teardown). Matches [`VncSession::close`] clearing the input queue; this
//! free function also works on a bare queue.
//!
//! # Secrets / Debug
//!
//! Reports and Fake sinks expose **counts only** (drained / dropped / coalesced
//! / kept / discarded). Never log keysyms, coordinates, or password material.

use std::fmt;

use crate::framebuffer::FramebufferSink;
use crate::input::{InputEvent, InputEventQueue, PointerEvent};
use crate::session::{VncSession, VncSessionState};
use crate::VncError;

/// Outcome of one resize drain/coalesce pass (counts only — no event bodies).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct InputResizeDrainReport {
    /// Events removed from the queue before reshape.
    pub drained: usize,
    /// Pointer events dropped as OOB for the new size.
    pub dropped_oob_pointer: usize,
    /// Intermediate pointer moves removed by same-button coalesce
    /// (`kept = drained - dropped_oob_pointer - coalesced_away`).
    pub coalesced_away: usize,
    /// Events re-enqueued after reshape.
    pub kept: usize,
}

impl InputResizeDrainReport {
    /// True when the queue ended empty (nothing kept).
    pub fn queue_empty_after(&self) -> bool {
        self.kept == 0
    }
}

/// Outcome of a disconnect drain (discard all — counts only).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct InputDisconnectDrainReport {
    /// Events drained and discarded (not sent).
    pub discarded: usize,
}

/// Lab Fake: records resize / disconnect drain reports (no RFB I/O).
#[derive(Clone, Default)]
pub struct FakeInputResizeSink {
    resize_reports: Vec<InputResizeDrainReport>,
    disconnect_reports: Vec<InputDisconnectDrainReport>,
}

impl FakeInputResizeSink {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn resize_reports(&self) -> &[InputResizeDrainReport] {
        &self.resize_reports
    }

    pub fn disconnect_reports(&self) -> &[InputDisconnectDrainReport] {
        &self.disconnect_reports
    }

    pub fn resize_len(&self) -> usize {
        self.resize_reports.len()
    }

    pub fn disconnect_len(&self) -> usize {
        self.disconnect_reports.len()
    }

    pub fn clear(&mut self) {
        self.resize_reports.clear();
        self.disconnect_reports.clear();
    }

    pub fn record_resize(&mut self, report: InputResizeDrainReport) {
        self.resize_reports.push(report);
    }

    pub fn record_disconnect(&mut self, report: InputDisconnectDrainReport) {
        self.disconnect_reports.push(report);
    }
}

impl fmt::Debug for FakeInputResizeSink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FakeInputResizeSink")
            .field("resize_reports", &self.resize_reports.len())
            .field("disconnect_reports", &self.disconnect_reports.len())
            .finish()
    }
}

/// True when a pointer coordinate lies inside `[0, width) × [0, height)`.
///
/// A zero-sized framebuffer rejects every pointer (fail-closed).
#[inline]
pub fn pointer_in_bounds(event: &PointerEvent, width: u16, height: u16) -> bool {
    width > 0 && height > 0 && event.x < width && event.y < height
}

/// Drain + coalesce pending input for a new framebuffer size.
///
/// See module-level **Coalesce policy**. Returns a count-only report.
pub fn drain_coalesce_on_resize(
    queue: &mut InputEventQueue,
    width: u16,
    height: u16,
) -> Result<InputResizeDrainReport, VncError> {
    let drained_events: Vec<InputEvent> = queue.drain(queue.len());
    let drained = drained_events.len();

    let mut kept_events = Vec::with_capacity(drained_events.len());
    let mut dropped_oob_pointer = 0usize;
    let mut coalesced_away = 0usize;

    for event in drained_events {
        match event {
            InputEvent::Pointer(p) => {
                if !pointer_in_bounds(&p, width, height) {
                    dropped_oob_pointer += 1;
                    continue;
                }
                if let Some(InputEvent::Pointer(prev)) = kept_events.last() {
                    if prev.buttons == p.buttons {
                        // Same-button consecutive move → replace with latest.
                        kept_events.pop();
                        coalesced_away += 1;
                    }
                }
                kept_events.push(InputEvent::Pointer(p));
            }
            InputEvent::Key(k) => {
                // Keys always kept in order — never coalesce down/up.
                kept_events.push(InputEvent::Key(k));
            }
        }
    }

    let kept = kept_events.len();
    // Coalesce only shrinks (or preserves) length, so re-enqueue always fits the
    // original capacity. On the impossible full-reject path, clear and fail closed
    // rather than leave a partial queue without an error.
    for event in kept_events {
        if let Err(e) = queue.enqueue(event) {
            queue.clear();
            return Err(e);
        }
    }

    Ok(InputResizeDrainReport {
        drained,
        dropped_oob_pointer,
        coalesced_away,
        kept,
    })
}

/// Drain and discard all pending input (disconnect / teardown fail-closed).
pub fn drain_discard_on_disconnect(queue: &mut InputEventQueue) -> InputDisconnectDrainReport {
    let discarded = queue.len();
    queue.clear();
    InputDisconnectDrainReport { discarded }
}

/// Resize session framebuffer, then drain/coalesce the input queue.
///
/// Fail-closed when not [`VncSessionState::Connected`] — framebuffer and queue
/// are left unchanged ([`VncError::NotConnected`]). On success, input is reshaped
/// **before** [`FramebufferSink::set_size`] so a hypothetical re-enqueue failure
/// does not leave a resized FB with a torn queue.
pub fn resize_session_framebuffer(
    session: &mut VncSession,
    width: u16,
    height: u16,
) -> Result<InputResizeDrainReport, VncError> {
    if session.state != VncSessionState::Connected {
        return Err(VncError::NotConnected);
    }
    let report = drain_coalesce_on_resize(&mut session.input, width, height)?;
    session.framebuffer.set_size(width, height);
    Ok(report)
}

/// Disconnect-path input drain: discard pending events without sending.
///
/// Does **not** change session state by itself — pair with [`VncSession::close`]
/// (which also clears the queue) or call on a bare queue. When the session is
/// already `Closed` / not connected, still drains whatever remains (idempotent).
pub fn disconnect_session_input(session: &mut VncSession) -> InputDisconnectDrainReport {
    drain_discard_on_disconnect(&mut session.input)
}

/// Owns a [`VncSession`] + [`FakeInputResizeSink`] for Lab / unit tests.
pub struct VncInputResizeGlue {
    session: VncSession,
    sink: FakeInputResizeSink,
}

impl fmt::Debug for VncInputResizeGlue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VncInputResizeGlue")
            .field("session", &self.session)
            .field("sink", &self.sink)
            .finish()
    }
}

impl VncInputResizeGlue {
    pub fn new(session: VncSession) -> Self {
        Self {
            session,
            sink: FakeInputResizeSink::new(),
        }
    }

    pub fn with_fake(options: crate::session::VncConnectOptions) -> Self {
        Self::new(VncSession::new(options))
    }

    pub fn with_fake_input_capacity(
        options: crate::session::VncConnectOptions,
        capacity: usize,
    ) -> Self {
        Self::new(VncSession::with_input_capacity(options, capacity))
    }

    pub fn session(&self) -> &VncSession {
        &self.session
    }

    pub fn session_mut(&mut self) -> &mut VncSession {
        &mut self.session
    }

    pub fn sink(&self) -> &FakeInputResizeSink {
        &self.sink
    }

    pub fn sink_mut(&mut self) -> &mut FakeInputResizeSink {
        &mut self.sink
    }

    pub fn into_parts(self) -> (VncSession, FakeInputResizeSink) {
        (self.session, self.sink)
    }

    pub fn mark_connected(&mut self, width: u16, height: u16) {
        self.session.mark_connected(width, height);
    }

    /// Resize FB + drain/coalesce input; record report on the Fake sink.
    pub fn on_framebuffer_resize(
        &mut self,
        width: u16,
        height: u16,
    ) -> Result<InputResizeDrainReport, VncError> {
        let report = resize_session_framebuffer(&mut self.session, width, height)?;
        self.sink.record_resize(report);
        Ok(report)
    }

    /// Close session (state → Closed, clears clipboard + input) then record a
    /// disconnect drain report for whatever was discarded (usually 0 after
    /// [`VncSession::close`] already cleared — call [`Self::drain_on_disconnect`]
    /// before close when the Fake must observe discarded counts).
    pub fn close(&mut self) {
        self.session.close();
    }

    /// Drain/discard pending input without changing session state; record Fake.
    pub fn drain_on_disconnect(&mut self) -> InputDisconnectDrainReport {
        let report = disconnect_session_input(&mut self.session);
        self.sink.record_disconnect(report);
        report
    }

    /// Drain then [`VncSession::close`] — Fake records discarded count from the
    /// pre-close drain (close's clear is then a no-op on an empty queue).
    pub fn disconnect(&mut self) -> InputDisconnectDrainReport {
        let report = self.drain_on_disconnect();
        self.session.close();
        report
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::VncPassword;
    use crate::input::{KeyEvent, PointerButtons, VncInputSink};
    use crate::session::VncConnectOptions;
    use std::net::{Ipv4Addr, SocketAddr};

    fn addr() -> SocketAddr {
        SocketAddr::from((Ipv4Addr::LOCALHOST, 5900))
    }

    fn opts() -> VncConnectOptions {
        VncConnectOptions::new(addr())
    }

    fn ptr(x: u16, y: u16, buttons: PointerButtons) -> PointerEvent {
        PointerEvent { x, y, buttons }
    }

    fn key(keysym: u32, down: bool) -> KeyEvent {
        KeyEvent { keysym, down }
    }

    #[test]
    fn coalesce_same_button_moves_keeps_last() {
        let mut q = InputEventQueue::new(16);
        q.enqueue_pointer(ptr(1, 1, PointerButtons::empty())).unwrap();
        q.enqueue_pointer(ptr(2, 2, PointerButtons::empty())).unwrap();
        q.enqueue_pointer(ptr(3, 3, PointerButtons::empty())).unwrap();
        let report = drain_coalesce_on_resize(&mut q, 100, 100).unwrap();
        assert_eq!(
            report,
            InputResizeDrainReport {
                drained: 3,
                dropped_oob_pointer: 0,
                coalesced_away: 2,
                kept: 1,
            }
        );
        assert_eq!(q.len(), 1);
        assert_eq!(
            q.dequeue(),
            Some(InputEvent::Pointer(ptr(3, 3, PointerButtons::empty())))
        );
    }

    #[test]
    fn different_buttons_are_not_coalesced() {
        let mut q = InputEventQueue::new(8);
        q.enqueue_pointer(ptr(1, 1, PointerButtons::LEFT)).unwrap();
        q.enqueue_pointer(ptr(2, 2, PointerButtons::empty())).unwrap();
        let report = drain_coalesce_on_resize(&mut q, 64, 64).unwrap();
        assert_eq!(report.kept, 2);
        assert_eq!(report.coalesced_away, 0);
        assert_eq!(
            q.dequeue(),
            Some(InputEvent::Pointer(ptr(1, 1, PointerButtons::LEFT)))
        );
        assert_eq!(
            q.dequeue(),
            Some(InputEvent::Pointer(ptr(2, 2, PointerButtons::empty())))
        );
    }

    #[test]
    fn oob_pointers_dropped_keys_preserved() {
        let mut q = InputEventQueue::new(16);
        q.enqueue_pointer(ptr(10, 10, PointerButtons::empty())).unwrap(); // OOB after resize
        q.enqueue_key(key(0x61, true)).unwrap();
        q.enqueue_pointer(ptr(1, 1, PointerButtons::LEFT)).unwrap(); // in bounds
        q.enqueue_key(key(0x61, false)).unwrap();
        let report = drain_coalesce_on_resize(&mut q, 8, 8).unwrap();
        assert_eq!(report.drained, 4);
        assert_eq!(report.dropped_oob_pointer, 1);
        assert_eq!(report.coalesced_away, 0);
        assert_eq!(report.kept, 3);
        assert_eq!(q.dequeue(), Some(InputEvent::Key(key(0x61, true))));
        assert_eq!(
            q.dequeue(),
            Some(InputEvent::Pointer(ptr(1, 1, PointerButtons::LEFT)))
        );
        assert_eq!(q.dequeue(), Some(InputEvent::Key(key(0x61, false))));
    }

    #[test]
    fn zero_size_framebuffer_drops_all_pointers_keeps_keys() {
        let mut q = InputEventQueue::new(8);
        q.enqueue_pointer(ptr(0, 0, PointerButtons::empty())).unwrap();
        q.enqueue_key(key(9, true)).unwrap();
        let report = drain_coalesce_on_resize(&mut q, 0, 0).unwrap();
        assert_eq!(report.dropped_oob_pointer, 1);
        assert_eq!(report.kept, 1);
        assert_eq!(q.dequeue(), Some(InputEvent::Key(key(9, true))));
    }

    #[test]
    fn edge_boundary_last_pixel_kept_exact_edge_oob() {
        // width=4 → valid x in 0..3; x=3 ok, x=4 OOB (no clamp).
        let mut q = InputEventQueue::new(8);
        q.enqueue_pointer(ptr(3, 3, PointerButtons::empty())).unwrap();
        q.enqueue_pointer(ptr(4, 0, PointerButtons::empty())).unwrap();
        q.enqueue_pointer(ptr(0, 4, PointerButtons::empty())).unwrap();
        let report = drain_coalesce_on_resize(&mut q, 4, 4).unwrap();
        assert_eq!(report.dropped_oob_pointer, 2);
        assert_eq!(report.kept, 1);
        assert_eq!(
            q.dequeue(),
            Some(InputEvent::Pointer(ptr(3, 3, PointerButtons::empty())))
        );
    }

    #[test]
    fn keys_interrupt_pointer_coalesce_runs() {
        // P,P (same buttons) → coalesce; Key; P — key breaks the coalesce run.
        let mut q = InputEventQueue::new(16);
        q.enqueue_pointer(ptr(1, 1, PointerButtons::empty())).unwrap();
        q.enqueue_pointer(ptr(2, 2, PointerButtons::empty())).unwrap();
        q.enqueue_key(key(1, true)).unwrap();
        q.enqueue_pointer(ptr(3, 3, PointerButtons::empty())).unwrap();
        let report = drain_coalesce_on_resize(&mut q, 100, 100).unwrap();
        assert_eq!(report.coalesced_away, 1);
        assert_eq!(report.kept, 3);
        assert_eq!(
            q.dequeue(),
            Some(InputEvent::Pointer(ptr(2, 2, PointerButtons::empty())))
        );
        assert_eq!(q.dequeue(), Some(InputEvent::Key(key(1, true))));
        assert_eq!(
            q.dequeue(),
            Some(InputEvent::Pointer(ptr(3, 3, PointerButtons::empty())))
        );
    }

    #[test]
    fn empty_queue_resize_is_noop_report() {
        let mut q = InputEventQueue::new(4);
        let report = drain_coalesce_on_resize(&mut q, 16, 16).unwrap();
        assert_eq!(report, InputResizeDrainReport::default());
        assert!(q.is_empty());
    }

    #[test]
    fn same_size_still_coalesces() {
        let mut q = InputEventQueue::new(8);
        q.enqueue_pointer(ptr(5, 5, PointerButtons::RIGHT)).unwrap();
        q.enqueue_pointer(ptr(6, 6, PointerButtons::RIGHT)).unwrap();
        let report = drain_coalesce_on_resize(&mut q, 64, 48).unwrap();
        assert_eq!(report.coalesced_away, 1);
        assert_eq!(report.kept, 1);
    }

    #[test]
    fn disconnect_discards_all_fail_closed() {
        let mut q = InputEventQueue::new(8);
        q.enqueue_pointer(ptr(1, 1, PointerButtons::LEFT)).unwrap();
        q.enqueue_key(key(2, true)).unwrap();
        let report = drain_discard_on_disconnect(&mut q);
        assert_eq!(report.discarded, 2);
        assert!(q.is_empty());
        // Idempotent.
        assert_eq!(
            drain_discard_on_disconnect(&mut q),
            InputDisconnectDrainReport { discarded: 0 }
        );
    }

    #[test]
    fn session_resize_fail_closed_when_not_connected() {
        let mut session = VncSession::new(opts());
        session
            .input
            .enqueue_pointer(ptr(1, 1, PointerButtons::empty()))
            .unwrap();
        assert_eq!(
            resize_session_framebuffer(&mut session, 32, 32),
            Err(VncError::NotConnected)
        );
        // Queue + FB unchanged on fail-closed.
        assert_eq!(session.input.len(), 1);
        assert_eq!(session.framebuffer.width(), 0);
        assert_eq!(session.state, VncSessionState::Idle);
    }

    #[test]
    fn session_resize_updates_fb_and_coalesces() {
        let mut session = VncSession::new(opts());
        session.mark_connected(100, 100);
        session
            .pointer(ptr(10, 10, PointerButtons::empty()))
            .unwrap();
        session
            .pointer(ptr(20, 20, PointerButtons::empty()))
            .unwrap();
        let report = resize_session_framebuffer(&mut session, 50, 50).unwrap();
        assert_eq!(session.framebuffer.width(), 50);
        assert_eq!(session.framebuffer.height(), 50);
        assert_eq!(report.coalesced_away, 1);
        assert_eq!(session.input.len(), 1);
    }

    #[test]
    fn session_resize_drops_oob_after_shrink() {
        let mut session = VncSession::new(opts());
        session.mark_connected(100, 100);
        session
            .pointer(ptr(80, 80, PointerButtons::LEFT))
            .unwrap();
        let report = resize_session_framebuffer(&mut session, 40, 40).unwrap();
        assert_eq!(report.dropped_oob_pointer, 1);
        assert!(session.input.is_empty());
    }

    #[test]
    fn glue_on_resize_records_fake_and_fail_closed() {
        let mut glue = VncInputResizeGlue::with_fake(opts());
        assert_eq!(
            glue.on_framebuffer_resize(10, 10),
            Err(VncError::NotConnected)
        );
        assert_eq!(glue.sink().resize_len(), 0);

        glue.mark_connected(64, 64);
        glue.session_mut()
            .pointer(ptr(1, 1, PointerButtons::empty()))
            .unwrap();
        glue.session_mut()
            .pointer(ptr(2, 2, PointerButtons::empty()))
            .unwrap();
        let report = glue.on_framebuffer_resize(32, 32).unwrap();
        assert_eq!(report.kept, 1);
        assert_eq!(glue.sink().resize_len(), 1);
        assert_eq!(glue.sink().resize_reports()[0], report);
    }

    #[test]
    fn glue_disconnect_drains_then_closes() {
        let mut glue = VncInputResizeGlue::with_fake_input_capacity(opts(), 8);
        glue.mark_connected(16, 16);
        glue.session_mut()
            .pointer(ptr(1, 1, PointerButtons::LEFT))
            .unwrap();
        glue.session_mut().key(key(0xff0d, true)).unwrap();
        let report = glue.disconnect();
        assert_eq!(report.discarded, 2);
        assert_eq!(glue.session().state, VncSessionState::Closed);
        assert!(glue.session().input.is_empty());
        assert_eq!(glue.sink().disconnect_len(), 1);
        // Further enqueue fail-closed.
        assert_eq!(
            glue.session_mut().pointer(ptr(0, 0, PointerButtons::empty())),
            Err(VncError::NotConnected)
        );
    }

    #[test]
    fn glue_close_alone_clears_without_fake_disconnect_record() {
        // Document interaction: close() clears queue; Fake disconnect only via drain paths.
        let mut glue = VncInputResizeGlue::with_fake(opts());
        glue.mark_connected(8, 8);
        glue.session_mut()
            .pointer(ptr(1, 1, PointerButtons::empty()))
            .unwrap();
        glue.close();
        assert!(glue.session().input.is_empty());
        assert_eq!(glue.sink().disconnect_len(), 0);
    }

    #[test]
    fn negotiating_resize_fail_closed() {
        let mut glue = VncInputResizeGlue::with_fake(opts());
        glue.session_mut()
            .negotiate_security(&[1])
            .expect("None security");
        assert_eq!(glue.session().state, VncSessionState::Negotiating);
        assert_eq!(
            glue.on_framebuffer_resize(8, 8),
            Err(VncError::NotConnected)
        );
        assert_eq!(glue.sink().resize_len(), 0);
    }

    #[test]
    fn debug_omits_event_bodies_and_password() {
        let mut glue = VncInputResizeGlue::with_fake(
            opts().with_password(VncPassword::new("sekrit!!").unwrap()),
        );
        glue.mark_connected(8, 8);
        glue.session_mut()
            .pointer(ptr(1, 1, PointerButtons::LEFT))
            .unwrap();
        glue.on_framebuffer_resize(8, 8).unwrap();
        let dbg = format!("{glue:?}");
        assert!(dbg.contains("VncInputResizeGlue"));
        assert!(dbg.contains("VncPassword(***)"));
        assert!(!dbg.contains("sekrit"));
        // Counts / capacity summary only — no keysym / coord dumps from reports.
        assert!(dbg.contains("FakeInputResizeSink"));
        let sink_dbg = format!("{:?}", glue.sink());
        assert!(sink_dbg.contains("resize_reports"));
        assert!(!sink_dbg.contains("keysym"));
    }

    #[test]
    fn pointer_in_bounds_helper() {
        let p = ptr(0, 0, PointerButtons::empty());
        assert!(!pointer_in_bounds(&p, 0, 10));
        assert!(!pointer_in_bounds(&p, 10, 0));
        assert!(pointer_in_bounds(&p, 1, 1));
        assert!(!pointer_in_bounds(&ptr(1, 0, PointerButtons::empty()), 1, 1));
    }

    #[test]
    fn report_invariant_held_after_mixed_pass() {
        let mut q = InputEventQueue::new(32);
        // 3 same-button moves (→ 1 kept, 2 coalesced), 1 OOB, 2 keys.
        q.enqueue_pointer(ptr(1, 1, PointerButtons::empty())).unwrap();
        q.enqueue_pointer(ptr(2, 2, PointerButtons::empty())).unwrap();
        q.enqueue_pointer(ptr(3, 3, PointerButtons::empty())).unwrap();
        q.enqueue_pointer(ptr(99, 99, PointerButtons::LEFT)).unwrap(); // OOB
        q.enqueue_key(key(1, true)).unwrap();
        q.enqueue_key(key(1, false)).unwrap();
        let report = drain_coalesce_on_resize(&mut q, 10, 10).unwrap();
        assert_eq!(report.drained, 6);
        assert_eq!(report.dropped_oob_pointer, 1);
        assert_eq!(report.coalesced_away, 2);
        assert_eq!(report.kept, 3);
        assert_eq!(
            report.kept,
            report.drained - report.dropped_oob_pointer - report.coalesced_away
        );
        assert!(!report.queue_empty_after());
    }

    #[test]
    fn oob_gap_allows_remaining_same_button_coalesce() {
        // In-bounds, OOB (dropped), in-bounds same buttons → coalesce across gap.
        let mut q = InputEventQueue::new(8);
        q.enqueue_pointer(ptr(1, 1, PointerButtons::empty())).unwrap();
        q.enqueue_pointer(ptr(50, 50, PointerButtons::empty())).unwrap();
        q.enqueue_pointer(ptr(2, 2, PointerButtons::empty())).unwrap();
        let report = drain_coalesce_on_resize(&mut q, 8, 8).unwrap();
        assert_eq!(report.dropped_oob_pointer, 1);
        assert_eq!(report.coalesced_away, 1);
        assert_eq!(report.kept, 1);
        assert_eq!(
            q.dequeue(),
            Some(InputEvent::Pointer(ptr(2, 2, PointerButtons::empty())))
        );
    }

    #[test]
    fn closed_session_resize_fail_closed_queue_intact() {
        let mut glue = VncInputResizeGlue::with_fake(opts());
        glue.mark_connected(16, 16);
        glue.session_mut()
            .pointer(ptr(1, 1, PointerButtons::LEFT))
            .unwrap();
        // Teardown without Fake disconnect record — close clears queue.
        glue.close();
        assert_eq!(glue.session().state, VncSessionState::Closed);
        assert!(glue.session().input.is_empty());
        // Re-seed queue while Closed (public field) — resize must not apply FB or coalesce.
        glue.session_mut()
            .input
            .enqueue_pointer(ptr(1, 1, PointerButtons::empty()))
            .unwrap();
        assert_eq!(
            glue.on_framebuffer_resize(8, 8),
            Err(VncError::NotConnected)
        );
        assert_eq!(glue.session().framebuffer.width(), 16); // unchanged
        assert_eq!(glue.session().input.len(), 1);
        assert_eq!(glue.sink().resize_len(), 0);
    }

    #[test]
    fn into_parts_round_trips() {
        let mut glue = VncInputResizeGlue::with_fake(opts());
        glue.mark_connected(4, 4);
        glue.on_framebuffer_resize(4, 4).unwrap();
        let (session, sink) = glue.into_parts();
        assert_eq!(session.state, VncSessionState::Connected);
        assert_eq!(sink.resize_len(), 1);
    }

    #[test]
    fn fake_clear_resets_reports_and_all_oob_empties_queue() {
        let mut glue = VncInputResizeGlue::with_fake(opts());
        glue.mark_connected(64, 64);
        glue.session_mut()
            .pointer(ptr(40, 40, PointerButtons::empty()))
            .unwrap();
        let report = glue.on_framebuffer_resize(8, 8).unwrap();
        assert!(report.queue_empty_after());
        assert_eq!(report.dropped_oob_pointer, 1);
        glue.drain_on_disconnect();
        assert_eq!(glue.sink().resize_len(), 1);
        assert_eq!(glue.sink().disconnect_len(), 1);
        glue.sink_mut().clear();
        assert_eq!(glue.sink().resize_len(), 0);
        assert_eq!(glue.sink().disconnect_len(), 0);
    }
}
