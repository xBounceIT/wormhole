use std::fmt;
use std::net::SocketAddr;

use crate::auth::{resolve_auth, VncAuthMethod, VncPassword};
use crate::clipboard_glue::CutTextPayload;
use crate::framebuffer::{FramebufferRect, FramebufferSink, RawPixelBuffer};
use crate::input::{InputEventQueue, KeyEvent, PointerEvent, VncInputSink};
use crate::protocol::{RfbSecurityType, RfbVersion};
use crate::VncError;

/// Connection options (host may be a tunnel loopback forwarder).
#[derive(Clone)]
pub struct VncConnectOptions {
    pub addr: SocketAddr,
    pub shared: bool,
    pub password: Option<VncPassword>,
    /// Security types the client is willing to accept (server offers ∩ client).
    pub accepted_security: Vec<RfbSecurityType>,
}

impl fmt::Debug for VncConnectOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VncConnectOptions")
            .field("addr", &self.addr)
            .field("shared", &self.shared)
            // VncPassword Debug is already redacted; keep explicit for auditability.
            .field("password", &self.password)
            .field("accepted_security", &self.accepted_security)
            .finish()
    }
}

impl VncConnectOptions {
    pub fn new(addr: SocketAddr) -> Self {
        Self {
            addr,
            shared: true,
            password: None,
            accepted_security: vec![RfbSecurityType::None, RfbSecurityType::VncAuth],
        }
    }

    pub fn with_password(mut self, password: VncPassword) -> Self {
        self.password = Some(password);
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VncSessionState {
    Idle,
    Negotiating,
    Connected,
    Closed,
}

/// In-process session stub: negotiates security selection + drives sink traits.
///
/// No TCP yet — call [`VncSession::negotiate_security`] with the server's offered
/// types, then [`VncSession::mark_connected`]. Live RFB I/O lands behind `engine`.
///
/// Framebuffer updates go through the Raw decode stub into [`RawPixelBuffer`];
/// pointer/key events enqueue on a bounded [`InputEventQueue`].
/// Clipboard cut-text: Fake outbound queue + local buffer via [`crate::clipboard_glue`].
pub struct VncSession {
    pub options: VncConnectOptions,
    pub state: VncSessionState,
    pub version: RfbVersion,
    pub security: Option<RfbSecurityType>,
    pub auth_method: Option<VncAuthMethod>,
    pub framebuffer: RawPixelBuffer,
    pub input: InputEventQueue,
    /// Fake outbound ClientCutText queue (clipboard glue; drained by a live engine later).
    pub outbound_cut_texts: Vec<CutTextPayload>,
    /// Last accepted inbound ServerCutText (local clipboard buffer).
    pub local_clipboard: Option<CutTextPayload>,
}

impl fmt::Debug for VncSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // `options` Debug redacts nested `VncPassword`; never dump password bytes
        // or the full pixel store (noise / accidental capture in logs).
        f.debug_struct("VncSession")
            .field("options", &self.options)
            .field("state", &self.state)
            .field("version", &self.version)
            .field("security", &self.security)
            .field("auth_method", &self.auth_method)
            .field(
                "framebuffer",
                &format_args!(
                    "{}x{} {:?}, damage={}",
                    self.framebuffer.width(),
                    self.framebuffer.height(),
                    self.framebuffer.format().kind,
                    self.framebuffer.damage().len()
                ),
            )
            .field(
                "input",
                &format_args!("{}/{}", self.input.len(), self.input.capacity()),
            )
            // Clipboard bodies are secrets-adjacent — lengths / counts only.
            .field("outbound_cut_texts", &self.outbound_cut_texts.len())
            .field(
                "local_clipboard_utf8_len",
                &self.local_clipboard.as_ref().map(CutTextPayload::utf8_len),
            )
            .finish()
    }
}

impl VncSession {
    pub fn new(options: VncConnectOptions) -> Self {
        Self {
            options,
            state: VncSessionState::Idle,
            version: RfbVersion::V3_8,
            security: None,
            auth_method: None,
            framebuffer: RawPixelBuffer::default(),
            input: InputEventQueue::default(),
            outbound_cut_texts: Vec::new(),
            local_clipboard: None,
        }
    }

    /// Create with an explicit input-queue capacity (tests / UI tuning).
    pub fn with_input_capacity(options: VncConnectOptions, capacity: usize) -> Self {
        let mut session = Self::new(options);
        session.input = InputEventQueue::new(capacity);
        session
    }

    pub fn negotiate_security(&mut self, offered: &[u8]) -> Result<RfbSecurityType, VncError> {
        if matches!(
            self.state,
            VncSessionState::Connected | VncSessionState::Closed
        ) {
            return Err(VncError::NotConnected);
        }
        let prior = self.state;
        self.state = VncSessionState::Negotiating;
        let outcome = (|| {
            let filtered: Vec<u8> = offered
                .iter()
                .copied()
                .filter(|t| {
                    self.options
                        .accepted_security
                        .iter()
                        .any(|a| a.as_u8() == *t)
                })
                .collect();
            let selected = RfbSecurityType::select(&filtered)?;
            let method = resolve_auth(selected, self.options.password.as_ref())?;
            Ok::<_, VncError>((selected, method))
        })();
        match outcome {
            Ok((selected, method)) => {
                self.security = Some(selected);
                self.auth_method = Some(method);
                Ok(selected)
            }
            Err(e) => {
                self.state = prior;
                Err(e)
            }
        }
    }

    pub fn mark_connected(&mut self, width: u16, height: u16) {
        self.framebuffer.set_size(width, height);
        self.state = VncSessionState::Connected;
    }

    /// Apply a Raw framebuffer rect (decode stub) into the pixel buffer.
    pub fn push_rect(&mut self, rect: FramebufferRect) -> Result<(), VncError> {
        if self.state != VncSessionState::Connected {
            return Err(VncError::NotConnected);
        }
        self.framebuffer.apply_rect(rect)
    }

    pub fn close(&mut self) {
        self.state = VncSessionState::Closed;
        self.input.clear();
        self.outbound_cut_texts.clear();
        self.local_clipboard = None;
    }

    /// Peek local clipboard text (test / Lab). Prefer length-only Debug elsewhere.
    pub fn local_clipboard_text(&self) -> Option<&str> {
        self.local_clipboard.as_ref().map(CutTextPayload::as_str)
    }

    /// Drain Fake outbound ClientCutText queue (engine / tests).
    pub fn take_outbound_cut_texts(&mut self) -> Vec<CutTextPayload> {
        std::mem::take(&mut self.outbound_cut_texts)
    }
}

impl VncInputSink for VncSession {
    fn pointer(&mut self, event: PointerEvent) -> Result<(), VncError> {
        if self.state != VncSessionState::Connected {
            return Err(VncError::NotConnected);
        }
        self.input.enqueue_pointer(event)
    }

    fn key(&mut self, event: KeyEvent) -> Result<(), VncError> {
        if self.state != VncSessionState::Connected {
            return Err(VncError::NotConnected);
        }
        self.input.enqueue_key(event)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::VncPassword;
    use crate::framebuffer::DamageRect;
    use bytes::Bytes;
    use std::net::{Ipv4Addr, SocketAddr};

    fn addr() -> SocketAddr {
        SocketAddr::from((Ipv4Addr::LOCALHOST, 5900))
    }

    #[test]
    fn no_auth_session_flow() {
        let mut session = VncSession::new(VncConnectOptions::new(addr()));
        assert_eq!(
            session.negotiate_security(&[1, 2]).unwrap(),
            RfbSecurityType::None
        );
        session.mark_connected(800, 600);
        session
            .push_rect(FramebufferRect {
                x: 0,
                y: 0,
                width: 1,
                height: 1,
                pixels: Bytes::from_static(&[0, 0, 0, 255]),
            })
            .unwrap();
        assert_eq!(session.framebuffer.width(), 800);
        assert_eq!(session.framebuffer.damage(), &[DamageRect::new(0, 0, 1, 1)]);
        session
            .pointer(PointerEvent {
                x: 10,
                y: 20,
                buttons: Default::default(),
            })
            .unwrap();
        assert_eq!(session.input.len(), 1);
    }

    #[test]
    fn password_auth_requires_secret() {
        let mut session = VncSession::new(VncConnectOptions::new(addr()));
        assert!(session.negotiate_security(&[2]).is_err());

        let mut session = VncSession::new(
            VncConnectOptions::new(addr()).with_password(VncPassword::new("secret").unwrap()),
        );
        assert_eq!(
            session.negotiate_security(&[2]).unwrap(),
            RfbSecurityType::VncAuth
        );
    }

    #[test]
    fn options_debug_redacts_password() {
        let opts =
            VncConnectOptions::new(addr()).with_password(VncPassword::new("sekrit!!").unwrap());
        let rendered = format!("{opts:?}");
        assert!(rendered.contains("VncPassword(***)"));
        assert!(!rendered.contains("sekrit"));
    }

    #[test]
    fn session_debug_redacts_password() {
        let mut session = VncSession::new(
            VncConnectOptions::new(addr()).with_password(VncPassword::new("sekrit!!").unwrap()),
        );
        session.mark_connected(16, 16);
        let rendered = format!("{session:?}");
        assert!(rendered.contains("VncPassword(***)"));
        assert!(!rendered.contains("sekrit"));
        // Summarize buffer; do not dump raw pixels.
        assert!(rendered.contains("16x16"));
        assert!(!rendered.contains("pixels:"));
    }

    #[test]
    fn negotiate_rejected_when_connected_or_closed() {
        let mut session = VncSession::new(VncConnectOptions::new(addr()));
        session.mark_connected(8, 8);
        assert_eq!(
            session.negotiate_security(&[1]),
            Err(VncError::NotConnected)
        );
        assert_eq!(session.state, VncSessionState::Connected);

        session.close();
        assert_eq!(
            session.negotiate_security(&[1]),
            Err(VncError::NotConnected)
        );
        assert_eq!(session.state, VncSessionState::Closed);
    }

    #[test]
    fn negotiate_failure_restores_prior_state() {
        let mut session = VncSession::new(VncConnectOptions::new(addr()));
        assert_eq!(session.state, VncSessionState::Idle);
        assert!(session.negotiate_security(&[16]).is_err());
        assert_eq!(session.state, VncSessionState::Idle);
        assert!(session.security.is_none());

        assert!(session.negotiate_security(&[2]).is_err()); // password required
        assert_eq!(session.state, VncSessionState::Idle);
    }

    #[test]
    fn input_rejected_before_connected() {
        let mut session = VncSession::new(VncConnectOptions::new(addr()));
        assert!(session
            .pointer(PointerEvent {
                x: 0,
                y: 0,
                buttons: Default::default(),
            })
            .is_err());
    }

    #[test]
    fn session_input_queue_bounds() {
        let mut session = VncSession::with_input_capacity(VncConnectOptions::new(addr()), 1);
        session.mark_connected(10, 10);
        session
            .pointer(PointerEvent {
                x: 1,
                y: 1,
                buttons: Default::default(),
            })
            .unwrap();
        assert_eq!(
            session.pointer(PointerEvent {
                x: 2,
                y: 2,
                buttons: Default::default(),
            }),
            Err(VncError::InputQueueFull { capacity: 1 })
        );
    }
}
