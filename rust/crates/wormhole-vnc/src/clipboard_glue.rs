//! VNC client↔server clipboard sync glue stub.
//!
//! Thin Lab stub (no GPUI / no live RFB):
//! - **Outbound:** host text → Fake [`VncSession`] ClientCutText send queue
//! - **Inbound:** ServerCutText event → session local clipboard buffer
//!
//! Size / empty policy mirrors terminal paste (`MAX_CLIPBOARD_PASTE_UTF8_BYTES`
//! in `wormhole-terminal`): soft **1 MiB UTF-8** cap; empty fail-closed with
//! **no** send / **no** local-buffer mutate. Exact limit is allowed.
//!
//! Clipboard bodies are secrets-adjacent (same posture as terminal paste /
//! `ClipboardHook` Debug): [`CutTextPayload`], errors, and session summaries
//! expose **lengths only** — never raw text.
//!
//! Fail-closed when the session is not [`VncSessionState::Connected`]
//! ([`VncError::NotConnected`]). C# `VncSessionService` still no-ops clipboard
//! today; this stub is the Rust contract for a future surface host.

use std::fmt;

use crate::session::{VncSession, VncSessionState};
use crate::VncError;

/// Soft UTF-8 byte cap for ClientCutText / ServerCutText (parity with terminal
/// paste `MAX_CLIPBOARD_PASTE_UTF8_BYTES` / C# `MaximumClipboardPasteUtf8Bytes`).
pub const MAX_VNC_CLIPBOARD_UTF8_BYTES: usize = 1024 * 1024;

/// Validated cut-text body. `Debug` / `Display` never include the text.
#[derive(Clone, PartialEq, Eq)]
pub struct CutTextPayload {
    text: String,
}

impl CutTextPayload {
    /// Validate non-empty + size cap. Does not require a connected session.
    pub fn try_new(text: impl Into<String>) -> Result<Self, VncError> {
        let text = text.into();
        validate_clipboard_utf8_len(text.len())?;
        Ok(Self { text })
    }

    pub fn as_str(&self) -> &str {
        &self.text
    }

    pub fn utf8_len(&self) -> usize {
        self.text.len()
    }

    pub fn into_string(self) -> String {
        self.text
    }
}

impl fmt::Debug for CutTextPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CutTextPayload")
            .field("utf8_len", &self.text.len())
            .finish()
    }
}

impl fmt::Display for CutTextPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CutTextPayload(utf8_len={})", self.text.len())
    }
}

/// Reject empty / oversize before any Fake send or local-buffer write.
///
/// Exact [`MAX_VNC_CLIPBOARD_UTF8_BYTES`] is allowed; one byte over is soft-rejected.
pub fn validate_clipboard_utf8_len(actual: usize) -> Result<(), VncError> {
    if actual == 0 {
        return Err(VncError::ClipboardEmpty);
    }
    if actual > MAX_VNC_CLIPBOARD_UTF8_BYTES {
        return Err(VncError::ClipboardTooLarge {
            actual,
            limit: MAX_VNC_CLIPBOARD_UTF8_BYTES,
        });
    }
    Ok(())
}

/// Outbound: validate host text → append ClientCutText on the Fake session.
///
/// | Condition | Behaviour |
/// |---|---|
/// | not Connected | [`VncError::NotConnected`] — no send |
/// | empty | [`VncError::ClipboardEmpty`] — no send |
/// | `> MAX_VNC_CLIPBOARD_UTF8_BYTES` | [`VncError::ClipboardTooLarge`] — no send |
/// | ok | push one [`CutTextPayload`] onto [`VncSession::outbound_cut_texts`] |
pub fn send_clipboard_to_session(session: &mut VncSession, text: &str) -> Result<(), VncError> {
    if session.state != VncSessionState::Connected {
        return Err(VncError::NotConnected);
    }
    let payload = CutTextPayload::try_new(text)?;
    session.outbound_cut_texts.push(payload);
    Ok(())
}

/// Inbound: validate ServerCutText → replace the session local clipboard buffer.
///
/// | Condition | Behaviour |
/// |---|---|
/// | not Connected | [`VncError::NotConnected`] — buffer unchanged |
/// | empty | [`VncError::ClipboardEmpty`] — buffer unchanged |
/// | oversize | [`VncError::ClipboardTooLarge`] — buffer unchanged |
/// | ok | replace [`VncSession::local_clipboard`] |
pub fn apply_server_cut_text(session: &mut VncSession, text: &str) -> Result<(), VncError> {
    if session.state != VncSessionState::Connected {
        return Err(VncError::NotConnected);
    }
    let payload = CutTextPayload::try_new(text)?;
    session.local_clipboard = Some(payload);
    Ok(())
}

/// Snapshot local clipboard UTF-8 length (no body) for Debug / Lab asserts.
pub fn local_clipboard_utf8_len(session: &VncSession) -> Option<usize> {
    session.local_clipboard.as_ref().map(CutTextPayload::utf8_len)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::VncConnectOptions;
    use std::net::{Ipv4Addr, SocketAddr};

    fn addr() -> SocketAddr {
        SocketAddr::from((Ipv4Addr::LOCALHOST, 5900))
    }

    fn connected_session() -> VncSession {
        let mut session = VncSession::new(VncConnectOptions::new(addr()));
        session.mark_connected(8, 8);
        session
    }

    #[test]
    fn outbound_send_records_on_fake_session() {
        let mut session = connected_session();
        send_clipboard_to_session(&mut session, "hello").unwrap();
        assert_eq!(session.outbound_cut_texts.len(), 1);
        assert_eq!(session.outbound_cut_texts[0].as_str(), "hello");
        assert!(session.local_clipboard.is_none());
    }

    #[test]
    fn inbound_cut_text_fills_local_buffer() {
        let mut session = connected_session();
        apply_server_cut_text(&mut session, "from-server").unwrap();
        assert_eq!(
            session.local_clipboard.as_ref().map(CutTextPayload::as_str),
            Some("from-server")
        );
        assert!(session.outbound_cut_texts.is_empty());
        assert_eq!(local_clipboard_utf8_len(&session), Some(11));
    }

    #[test]
    fn inbound_replaces_prior_local_buffer() {
        let mut session = connected_session();
        apply_server_cut_text(&mut session, "first").unwrap();
        apply_server_cut_text(&mut session, "second").unwrap();
        assert_eq!(
            session.local_clipboard.as_ref().map(CutTextPayload::as_str),
            Some("second")
        );
    }

    #[test]
    fn empty_outbound_fail_closed_no_send() {
        let mut session = connected_session();
        assert_eq!(
            send_clipboard_to_session(&mut session, ""),
            Err(VncError::ClipboardEmpty)
        );
        assert!(session.outbound_cut_texts.is_empty());
    }

    #[test]
    fn empty_inbound_fail_closed_buffer_unchanged() {
        let mut session = connected_session();
        apply_server_cut_text(&mut session, "keep").unwrap();
        assert_eq!(
            apply_server_cut_text(&mut session, ""),
            Err(VncError::ClipboardEmpty)
        );
        assert_eq!(
            session.local_clipboard.as_ref().map(CutTextPayload::as_str),
            Some("keep")
        );
    }

    #[test]
    fn oversize_outbound_fail_closed_no_send() {
        let mut session = connected_session();
        let huge = "x".repeat(MAX_VNC_CLIPBOARD_UTF8_BYTES + 1);
        assert_eq!(
            send_clipboard_to_session(&mut session, &huge),
            Err(VncError::ClipboardTooLarge {
                actual: MAX_VNC_CLIPBOARD_UTF8_BYTES + 1,
                limit: MAX_VNC_CLIPBOARD_UTF8_BYTES,
            })
        );
        assert!(session.outbound_cut_texts.is_empty());
    }

    #[test]
    fn oversize_inbound_fail_closed_buffer_unchanged() {
        let mut session = connected_session();
        apply_server_cut_text(&mut session, "keep").unwrap();
        let huge = "y".repeat(MAX_VNC_CLIPBOARD_UTF8_BYTES + 1);
        assert_eq!(
            apply_server_cut_text(&mut session, &huge),
            Err(VncError::ClipboardTooLarge {
                actual: MAX_VNC_CLIPBOARD_UTF8_BYTES + 1,
                limit: MAX_VNC_CLIPBOARD_UTF8_BYTES,
            })
        );
        assert_eq!(
            session.local_clipboard.as_ref().map(CutTextPayload::as_str),
            Some("keep")
        );
    }

    #[test]
    fn exact_limit_allowed_both_directions() {
        let mut session = connected_session();
        let exact = "z".repeat(MAX_VNC_CLIPBOARD_UTF8_BYTES);
        send_clipboard_to_session(&mut session, &exact).unwrap();
        apply_server_cut_text(&mut session, &exact).unwrap();
        assert_eq!(session.outbound_cut_texts[0].utf8_len(), MAX_VNC_CLIPBOARD_UTF8_BYTES);
        assert_eq!(local_clipboard_utf8_len(&session), Some(MAX_VNC_CLIPBOARD_UTF8_BYTES));
    }

    #[test]
    fn fail_closed_when_not_connected() {
        let mut session = VncSession::new(VncConnectOptions::new(addr()));
        assert_eq!(
            send_clipboard_to_session(&mut session, "x"),
            Err(VncError::NotConnected)
        );
        assert_eq!(
            apply_server_cut_text(&mut session, "x"),
            Err(VncError::NotConnected)
        );
        assert!(session.outbound_cut_texts.is_empty());
        assert!(session.local_clipboard.is_none());

        session
            .negotiate_security(&[1])
            .expect("None security accepted");
        assert_eq!(session.state, VncSessionState::Negotiating);
        assert_eq!(
            send_clipboard_to_session(&mut session, "x"),
            Err(VncError::NotConnected)
        );
    }

    #[test]
    fn fail_closed_after_close_clears_clipboard_state() {
        let mut session = connected_session();
        send_clipboard_to_session(&mut session, "out").unwrap();
        apply_server_cut_text(&mut session, "in").unwrap();
        assert_eq!(session.outbound_cut_texts.len(), 1);
        assert!(session.local_clipboard.is_some());

        session.close();
        assert!(session.outbound_cut_texts.is_empty());
        assert!(session.local_clipboard.is_none());
        assert_eq!(
            send_clipboard_to_session(&mut session, "again"),
            Err(VncError::NotConnected)
        );
        assert_eq!(
            apply_server_cut_text(&mut session, "again"),
            Err(VncError::NotConnected)
        );
        assert!(session.outbound_cut_texts.is_empty());
        assert!(session.local_clipboard.is_none());
    }

    #[test]
    fn cut_text_payload_and_errors_omit_body_in_debug() {
        let secret = "sekrit-clipboard-body!!";
        let payload = CutTextPayload::try_new(secret).unwrap();
        let dbg = format!("{payload:?}");
        assert!(dbg.contains("utf8_len"));
        assert!(!dbg.contains("sekrit"));
        let display = format!("{payload}");
        assert!(!display.contains("sekrit"));

        let empty_err = format!("{:?}", VncError::ClipboardEmpty);
        assert!(!empty_err.contains("sekrit"));
        let too_large = format!(
            "{:?}",
            VncError::ClipboardTooLarge {
                actual: 99,
                limit: MAX_VNC_CLIPBOARD_UTF8_BYTES,
            }
        );
        assert!(too_large.contains("99"));
        assert!(!too_large.contains("sekrit"));
    }

    #[test]
    fn session_debug_summarizes_clipboard_lengths_only() {
        let mut session = connected_session();
        let secret = "sekrit-clipboard-body!!";
        send_clipboard_to_session(&mut session, secret).unwrap();
        apply_server_cut_text(&mut session, secret).unwrap();
        let dbg = format!("{session:?}");
        assert!(dbg.contains("outbound_cut_texts"));
        assert!(dbg.contains("local_clipboard_utf8_len"));
        assert!(!dbg.contains("sekrit"));
        assert!(!dbg.contains(secret));
    }

    #[test]
    fn validate_helper_matches_try_new() {
        assert_eq!(
            validate_clipboard_utf8_len(0),
            Err(VncError::ClipboardEmpty)
        );
        assert!(validate_clipboard_utf8_len(1).is_ok());
        assert!(validate_clipboard_utf8_len(MAX_VNC_CLIPBOARD_UTF8_BYTES).is_ok());
        assert_eq!(
            validate_clipboard_utf8_len(MAX_VNC_CLIPBOARD_UTF8_BYTES + 1),
            Err(VncError::ClipboardTooLarge {
                actual: MAX_VNC_CLIPBOARD_UTF8_BYTES + 1,
                limit: MAX_VNC_CLIPBOARD_UTF8_BYTES,
            })
        );
    }
}
