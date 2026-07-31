//! Paste request → clipboard → chunk bounds → [`TerminalSession`] write glue.
//!
//! Thin Lab stub: wires existing [`read_paste_text`] / [`build_paste_transaction`]
//! (chunk size [`crate::CLIPBOARD_PASTE_CHUNK_CHARS`], soft 1 MiB cap) into session
//! `write` calls. Uses [`crate::FakeClipboard`] + [`FakeTerminalSession`] in tests.
//!
//! **Not** the full C# `TerminalBridge` pump (no WebView2 `paste-drain` /
//! `paste-begin` / `paste-chunk` / `paste-end` posting). Host paste still runs
//! only on an explicit page [`ClipboardHook::PasteRequest`] — never auto-send.
//! Empty / oversize clipboard fail closed with **no** session writes.
//!
//! Paste bodies are secrets-adjacent: [`PasteToSessionResult`] / errors / `Debug`
//! carry sizes and ids only (same redaction posture as [`crate::FakeClipboard`] /
//! [`ClipboardHook`]).

use crate::clipboard::{
    build_paste_transaction, read_paste_text, ClipboardError, HostClipboard,
};
use crate::messages::ClipboardHook;
use crate::session::{FakeTerminalSession, TerminalSession};
use crate::TerminalError;
use crate::TerminalMessage;

/// Outcome of a successful paste → session write (no body text).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PasteToSessionResult {
    pub request_id: i64,
    pub force: bool,
    pub total_utf8_bytes: usize,
    pub chunks_written: usize,
}

/// Errors from paste → session glue (clipboard or session write).
///
/// Display / Debug must never include clipboard or write body text.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PasteSessionError {
    #[error(transparent)]
    Clipboard(#[from] ClipboardError),
    #[error("terminal session rejected paste write: {0}")]
    Session(#[from] TerminalError),
    /// Defensive: paste transaction emitted a non begin/chunk/end frame.
    /// Message is body-free by construction (no frame payload echoed).
    #[error("unexpected paste transaction frame")]
    UnexpectedFrame,
}

/// Apply a page paste request: read clipboard, chunk, write each chunk to `session`.
///
/// | Clipboard | Behaviour |
/// |---|---|
/// | empty / no text | [`ClipboardError::Empty`] — zero writes |
/// | `> MAX_CLIPBOARD_PASTE_UTF8_BYTES` | [`ClipboardError::TooLarge`] — zero writes |
/// | ok | one `session.write` per paste chunk (CRLF-aware bounds) |
///
/// If [`TerminalSession::is_closing`] at entry, fails with
/// [`TerminalError::Closing`] **without** reading the clipboard (so a one-shot
/// Fake clipboard remains available for a retry). Mid-flight close between
/// chunks also fails closed (partial writes may already have landed).
///
/// `force` is recorded on the result for wire parity; this stub does not wrap
/// bracketed-paste ESC sequences (page / xterm owns that in production).
pub async fn paste_request_to_session(
    request_id: i64,
    force: bool,
    clipboard: &mut dyn HostClipboard,
    session: &dyn TerminalSession,
) -> Result<PasteToSessionResult, PasteSessionError> {
    if session.is_closing() {
        return Err(PasteSessionError::Session(TerminalError::Closing));
    }

    let text = read_paste_text(clipboard)?;
    let frames = build_paste_transaction(request_id, force, &text)?;
    let total_utf8_bytes = text.len();
    let chunks_written = write_paste_chunks(session, &frames).await?;

    debug_assert!(
        chunks_written > 0 && total_utf8_bytes > 0,
        "read_paste_text rejects empty; non-empty paste must emit ≥1 chunk"
    );

    Ok(PasteToSessionResult {
        request_id,
        force,
        total_utf8_bytes,
        chunks_written,
    })
}

/// Write each `PasteChunk` body to `session`; fail closed on closing / bad frames.
///
/// `pub(crate)` so unit tests can inject hostile frames without going through
/// [`build_paste_transaction`].
pub(crate) async fn write_paste_chunks(
    session: &dyn TerminalSession,
    frames: &[TerminalMessage],
) -> Result<usize, PasteSessionError> {
    let mut chunks_written = 0usize;

    for frame in frames {
        match frame {
            TerminalMessage::Clipboard(ClipboardHook::PasteChunk { data, .. }) => {
                if session.is_closing() {
                    return Err(PasteSessionError::Session(TerminalError::Closing));
                }
                session.write(data.as_ref()).await?;
                chunks_written += 1;
            }
            TerminalMessage::Clipboard(
                ClipboardHook::PasteBegin { .. } | ClipboardHook::PasteEnd { .. },
            ) => {
                // Wire framing only — session path writes chunk bodies.
            }
            // Body-free: do not format `frame` into the error (could carry
            // selection / chunk payloads even when Debug redacts).
            _ => return Err(PasteSessionError::UnexpectedFrame),
        }
    }

    Ok(chunks_written)
}

/// Convenience: paste through [`FakeClipboard`] + [`FakeTerminalSession`].
///
/// Intended for unit tests and Lab harnesses (no OS clipboard, no GPUI).
pub async fn paste_request_to_fake_session(
    request_id: i64,
    force: bool,
    clipboard: &mut crate::FakeClipboard,
    session: &FakeTerminalSession,
) -> Result<PasteToSessionResult, PasteSessionError> {
    paste_request_to_session(request_id, force, clipboard, session).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clipboard::CLIPBOARD_PASTE_CHUNK_CHARS;
    use crate::messages::MAX_CLIPBOARD_PASTE_UTF8_BYTES;
    use crate::FakeClipboard;
    use bytes::Bytes;

    #[tokio::test]
    async fn paste_writes_chunked_body_to_fake_session() {
        let text = "a".repeat(CLIPBOARD_PASTE_CHUNK_CHARS + 3);
        let mut clip = FakeClipboard::with_text(text.clone());
        let session = FakeTerminalSession::new();

        let result = paste_request_to_fake_session(42, true, &mut clip, &session)
            .await
            .unwrap();
        assert_eq!(result.request_id, 42);
        assert!(result.force);
        assert_eq!(result.total_utf8_bytes, text.len());
        assert_eq!(result.chunks_written, 2);
        assert_eq!(session.writes_count(), 2);
        assert_eq!(session.total_bytes_written(), text.len());
        assert_eq!(session.reassembled_utf8(), text);

        let writes = session.writes();
        assert_eq!(writes[0].len(), CLIPBOARD_PASTE_CHUNK_CHARS);
        assert_eq!(writes[1].len(), 3);
    }

    #[tokio::test]
    async fn empty_clipboard_fail_closed_no_writes() {
        let mut clip = FakeClipboard::new();
        let session = FakeTerminalSession::new();
        let err = paste_request_to_session(1, false, &mut clip, &session)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            PasteSessionError::Clipboard(ClipboardError::Empty)
        ));
        assert_eq!(session.writes_count(), 0);
    }

    #[tokio::test]
    async fn empty_string_clipboard_fail_closed_no_writes() {
        let mut clip = FakeClipboard::with_text("");
        let session = FakeTerminalSession::new();
        let err = paste_request_to_session(1, false, &mut clip, &session)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            PasteSessionError::Clipboard(ClipboardError::Empty)
        ));
        assert_eq!(session.writes_count(), 0);
    }

    #[tokio::test]
    async fn oversize_fail_closed_no_writes() {
        let huge = "x".repeat(MAX_CLIPBOARD_PASTE_UTF8_BYTES + 1);
        let mut clip = FakeClipboard::with_text(huge);
        let session = FakeTerminalSession::new();
        let err = paste_request_to_session(9, false, &mut clip, &session)
            .await
            .unwrap_err();
        match &err {
            PasteSessionError::Clipboard(ClipboardError::TooLarge { actual, limit }) => {
                assert_eq!(*actual, MAX_CLIPBOARD_PASTE_UTF8_BYTES + 1);
                assert_eq!(*limit, MAX_CLIPBOARD_PASTE_UTF8_BYTES);
            }
            other => panic!("expected TooLarge, got {other:?}"),
        }
        assert_eq!(session.writes_count(), 0);
        // Error / Debug must not leak the paste body.
        let msg = err.to_string();
        assert!(!msg.contains("xxxxx"));
        let dbg = format!("{err:?}");
        assert!(!dbg.contains("xxxxx"));
    }

    #[tokio::test]
    async fn exact_max_paste_writes() {
        let exact = "y".repeat(MAX_CLIPBOARD_PASTE_UTF8_BYTES);
        let mut clip = FakeClipboard::with_text(exact.clone());
        let session = FakeTerminalSession::new();
        let result = paste_request_to_session(2, false, &mut clip, &session)
            .await
            .unwrap();
        assert_eq!(result.total_utf8_bytes, MAX_CLIPBOARD_PASTE_UTF8_BYTES);
        assert!(result.chunks_written >= 1);
        assert_eq!(session.total_bytes_written(), MAX_CLIPBOARD_PASTE_UTF8_BYTES);
        assert_eq!(session.reassembled_utf8(), exact);
    }

    #[tokio::test]
    async fn closing_session_fail_closed_without_write() {
        let mut clip = FakeClipboard::with_text("secret-token");
        let session = FakeTerminalSession::new();
        session.mark_closing();
        let err = paste_request_to_session(3, false, &mut clip, &session)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            PasteSessionError::Session(TerminalError::Closing)
        ));
        assert_eq!(session.writes_count(), 0);
        // Clipboard left unread so a retry on a live session can still paste.
        assert_eq!(clip.peek().as_deref(), Some("secret-token"));
    }

    #[tokio::test]
    async fn closing_mid_paste_fail_closed_after_partial_writes() {
        let text = "a".repeat(CLIPBOARD_PASTE_CHUNK_CHARS + 5);
        let mut clip = FakeClipboard::with_text(text.clone());
        let session = FakeTerminalSession::new();
        session.close_after_n_writes(1);

        let err = paste_request_to_session(5, false, &mut clip, &session)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            PasteSessionError::Session(TerminalError::Closing)
        ));
        assert_eq!(session.writes_count(), 1);
        assert_eq!(session.total_bytes_written(), CLIPBOARD_PASTE_CHUNK_CHARS);
        assert_eq!(
            session.reassembled_utf8(),
            &text[..CLIPBOARD_PASTE_CHUNK_CHARS]
        );
        assert!(session.is_closing());
        let msg = err.to_string();
        assert!(!msg.contains("aaaa"));
        let dbg = format!("{err:?}");
        assert!(!dbg.contains("aaaa"));
    }

    #[tokio::test]
    async fn result_and_fake_debug_omit_paste_body() {
        let mut clip = FakeClipboard::with_text("super-secret-paste-body");
        let session = FakeTerminalSession::new();
        let result = paste_request_to_session(7, false, &mut clip, &session)
            .await
            .unwrap();
        let result_dbg = format!("{result:?}");
        assert!(!result_dbg.contains("super-secret"));
        assert!(result_dbg.contains("total_utf8_bytes"));

        let session_dbg = format!("{session:?}");
        assert!(session_dbg.contains("FakeTerminalSession"));
        assert!(!session_dbg.contains("super-secret"));
        assert!(session_dbg.contains("utf8_len") || session_dbg.contains("writes_count"));
    }

    #[tokio::test]
    async fn crlf_chunk_boundary_preserved_in_session_writes() {
        let mut text = "a".repeat(CLIPBOARD_PASTE_CHUNK_CHARS - 1);
        text.push_str("\r\nb");
        let mut clip = FakeClipboard::with_text(text.clone());
        let session = FakeTerminalSession::new();
        let result = paste_request_to_session(11, false, &mut clip, &session)
            .await
            .unwrap();
        assert!(result.chunks_written >= 2);
        let writes = session.writes();
        let as_str: Vec<String> = writes
            .iter()
            .map(|w| String::from_utf8(w.clone()).unwrap())
            .collect();
        assert_eq!(as_str.concat(), text);
        assert!(
            !as_str
                .windows(2)
                .any(|w| w[0].ends_with('\r') && w[1].starts_with('\n')),
            "CRLF must not straddle session write chunks: {as_str:?}"
        );
    }

    #[tokio::test]
    async fn exact_chunk_size_is_single_write() {
        let text = "z".repeat(CLIPBOARD_PASTE_CHUNK_CHARS);
        let mut clip = FakeClipboard::with_text(text.clone());
        let session = FakeTerminalSession::new();
        let result = paste_request_to_session(4, false, &mut clip, &session)
            .await
            .unwrap();
        assert_eq!(result.chunks_written, 1);
        assert_eq!(session.writes_count(), 1);
        assert_eq!(session.reassembled_utf8(), text);
    }

    #[tokio::test]
    async fn unicode_scalar_boundary_reassembles() {
        // Multibyte scalars around the production chunk edge must not split
        // mid-code-unit when delivered via session writes.
        let mut text = "a".repeat(CLIPBOARD_PASTE_CHUNK_CHARS - 1);
        text.push('é'); // 2-byte UTF-8 scalar
        text.push_str("tail");
        let mut clip = FakeClipboard::with_text(text.clone());
        let session = FakeTerminalSession::new();
        let result = paste_request_to_session(13, false, &mut clip, &session)
            .await
            .unwrap();
        assert!(result.chunks_written >= 2);
        assert_eq!(session.reassembled_utf8(), text);
        for w in session.writes() {
            assert!(
                std::str::from_utf8(&w).is_ok(),
                "session write must be valid UTF-8 (no mid-scalar split)"
            );
        }
    }

    #[tokio::test]
    async fn unexpected_frame_fail_closed_no_body_in_error() {
        let session = FakeTerminalSession::new();
        let frames = vec![TerminalMessage::Clipboard(ClipboardHook::SelectionCopy {
            data: Bytes::from_static(b"super-secret-selection"),
        })];
        let err = write_paste_chunks(&session, &frames).await.unwrap_err();
        assert_eq!(err, PasteSessionError::UnexpectedFrame);
        assert_eq!(session.writes_count(), 0);
        let msg = err.to_string();
        assert!(!msg.contains("super-secret"));
        let dbg = format!("{err:?}");
        assert!(!dbg.contains("super-secret"));
    }

    #[tokio::test]
    async fn small_paste_single_chunk() {
        let mut clip = FakeClipboard::with_text("hi");
        let session = FakeTerminalSession::new();
        let result = paste_request_to_session(1, false, &mut clip, &session)
            .await
            .unwrap();
        assert_eq!(result.chunks_written, 1);
        assert_eq!(session.reassembled_utf8(), "hi");
    }
}
