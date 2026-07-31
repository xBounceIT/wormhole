//! Host clipboard read/write for the xterm.js terminal bridge.
//!
//! Paste delivery over the wire (`paste-begin` / `paste-chunk` / …) already
//! lives in [`crate::messages`]. This module is the OS-facing side: read text
//! for paste requests and write selection-copy payloads.
//!
//! - [`HostClipboard`] — trait used by the bridge pump.
//! - [`FakeClipboard`] — in-memory impl for unit tests (always available).
//! - [`win32::Win32Clipboard`] — feature `clipboard-win` + `cfg(windows)` stub.
//!
//! Clipboard bodies are secrets-adjacent — never log raw read/write payloads.
//! Host paste assembly runs only in response to a page `PasteRequest` (`p:`);
//! this crate never auto-sends clipboard contents into a session.

use crate::messages::{ClipboardHook, TerminalMessage, MAX_CLIPBOARD_PASTE_UTF8_BYTES};
use crate::TerminalError;
use bytes::Bytes;
use std::sync::{Arc, Mutex};

/// Chunk size for paste body frames (`TerminalBridge.ClipboardPasteChunkCharacters`).
///
/// C# slices by UTF-16-ish `String.Length` characters; we chunk by Unicode
/// scalar values (chars) which is the closest portable match for BMP text.
pub const CLIPBOARD_PASTE_CHUNK_CHARS: usize = 16 * 1024;

/// Errors from host clipboard I/O.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ClipboardError {
    /// Clipboard is empty or has no text format.
    #[error("clipboard has no text")]
    Empty,
    /// Clipboard content exceeds the paste size cap.
    #[error("clipboard text exceeds paste limit ({actual} > {limit})")]
    TooLarge { actual: usize, limit: usize },
    /// Platform / API failure (message must not include clipboard body).
    #[error("clipboard operation failed: {0}")]
    Failed(String),
    /// Feature / platform not available in this build.
    #[error("clipboard backend unavailable: {0}")]
    Unavailable(&'static str),
}

impl From<ClipboardError> for TerminalError {
    fn from(value: ClipboardError) -> Self {
        TerminalError::Other(value.to_string())
    }
}

/// Host clipboard read/write used by the terminal bridge paste / copy path.
pub trait HostClipboard: Send {
    /// Read Unicode text from the system (or fake) clipboard.
    fn read_text(&mut self) -> Result<String, ClipboardError>;

    /// Write Unicode text (selection copy). `text` must not be logged by impls.
    fn write_text(&mut self, text: &str) -> Result<(), ClipboardError>;
}

/// In-memory clipboard for tests and non-Windows hosts.
#[derive(Clone, Default)]
pub struct FakeClipboard {
    inner: Arc<Mutex<Option<String>>>,
}

impl FakeClipboard {
    /// Empty clipboard.
    pub fn new() -> Self {
        Self::default()
    }

    /// Seed with initial text.
    pub fn with_text(text: impl Into<String>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Some(text.into()))),
        }
    }

    /// Snapshot current contents (test helper).
    pub fn peek(&self) -> Option<String> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
}

impl HostClipboard for FakeClipboard {
    fn read_text(&mut self) -> Result<String, ClipboardError> {
        let guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        guard.clone().ok_or(ClipboardError::Empty)
    }

    fn write_text(&mut self, text: &str) -> Result<(), ClipboardError> {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        *guard = Some(text.to_string());
        Ok(())
    }
}

impl std::fmt::Debug for FakeClipboard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let len = self
            .inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .map(|s| s.len());
        f.debug_struct("FakeClipboard")
            .field("utf8_len", &len)
            .finish()
    }
}

/// Read clipboard text and reject oversize pastes (C# `MaximumClipboardPasteUtf8Bytes`).
///
/// A zero-length string maps to [`ClipboardError::Empty`] (C# `IsNullOrEmpty`
/// early-return before `PostClipboardPasteInChunks`). Exact
/// [`MAX_CLIPBOARD_PASTE_UTF8_BYTES`] is allowed; one byte over is soft-rejected.
pub fn read_paste_text(clipboard: &mut dyn HostClipboard) -> Result<String, ClipboardError> {
    let text = clipboard.read_text()?;
    if text.is_empty() {
        return Err(ClipboardError::Empty);
    }
    let actual = text.len();
    if actual > MAX_CLIPBOARD_PASTE_UTF8_BYTES {
        return Err(ClipboardError::TooLarge {
            actual,
            limit: MAX_CLIPBOARD_PASTE_UTF8_BYTES,
        });
    }
    Ok(text)
}

/// Split paste UTF-8 into wire `paste-chunk` payloads (character-sized slices).
///
/// Returns an ordered list of [`TerminalMessage::Clipboard`] frames:
/// `PasteBegin` → zero or more `PasteChunk` → `PasteEnd`.
///
/// Empty `text` is wire-legal (`paste-begin` with `total_utf8_bytes=0`, no
/// chunks, then `paste-end`). The host clipboard path normally never reaches
/// this for empty reads — see [`read_paste_text`].
///
/// Chunking mirrors C# `PostClipboardPasteInChunks`: windows of
/// [`CLIPBOARD_PASTE_CHUNK_CHARS`] Unicode scalars, never splitting a CRLF pair
/// across chunks. `max_chars == 0` yields no chunks (const is always 16 KiB).
pub fn build_paste_transaction(
    request_id: i64,
    force: bool,
    text: &str,
) -> Result<Vec<TerminalMessage>, ClipboardError> {
    let total_utf8_bytes = text.len();
    if total_utf8_bytes > MAX_CLIPBOARD_PASTE_UTF8_BYTES {
        return Err(ClipboardError::TooLarge {
            actual: total_utf8_bytes,
            limit: MAX_CLIPBOARD_PASTE_UTF8_BYTES,
        });
    }

    debug_assert!(
        CLIPBOARD_PASTE_CHUNK_CHARS > 0,
        "CLIPBOARD_PASTE_CHUNK_CHARS must be non-zero"
    );

    let mut out = Vec::new();
    out.push(TerminalMessage::Clipboard(ClipboardHook::PasteBegin {
        request_id,
        force,
        total_utf8_bytes: total_utf8_bytes as u64,
    }));

    for chunk in utf8_char_chunks(text, CLIPBOARD_PASTE_CHUNK_CHARS) {
        debug_assert!(!chunk.is_empty(), "paste chunker must not emit empty slices");
        out.push(TerminalMessage::Clipboard(ClipboardHook::PasteChunk {
            request_id,
            data: Bytes::copy_from_slice(chunk.as_bytes()),
        }));
    }

    out.push(TerminalMessage::Clipboard(ClipboardHook::PasteEnd {
        request_id,
    }));
    Ok(out)
}

/// Iterate `text` in windows of at most `max_chars` Unicode scalar values.
///
/// Never splits `\r\n` across chunk boundaries (C# surrogate/CRLF guard; Rust
/// scalars already keep surrogate pairs intact). When `max_chars == 0` or
/// `text` is empty, yields nothing. Never yields an empty slice.
fn utf8_char_chunks(text: &str, max_chars: usize) -> impl Iterator<Item = &str> {
    std::iter::from_fn({
        let mut rest = text;
        move || {
            if rest.is_empty() || max_chars == 0 {
                return None;
            }
            let mut end = 0;
            let mut count = 0;
            for (i, ch) in rest.char_indices() {
                if count == max_chars {
                    end = i;
                    break;
                }
                count += 1;
                end = i + ch.len_utf8();
            }
            if count < max_chars {
                end = rest.len();
            } else if end > 0 && end < rest.len() {
                // Keep CRLF together: if this window would end on `\r` and the
                // next scalar is `\n`, pull the CR into the following chunk —
                // unless that would empty this window (max_chars == 1), in
                // which case take the whole `\r\n` (one char over budget).
                let prefix = &rest[..end];
                if prefix.ends_with('\r') && rest[end..].starts_with('\n') {
                    let pulled = end - '\r'.len_utf8();
                    if pulled > 0 {
                        end = pulled;
                    } else {
                        end += '\n'.len_utf8();
                    }
                }
            }
            // Progress guarantee: never return an empty chunk.
            if end == 0 {
                return None;
            }
            let (chunk, next) = rest.split_at(end);
            rest = next;
            Some(chunk)
        }
    })
}

/// Win32 clipboard stub (`OpenClipboard` / `CF_UNICODETEXT`).
#[cfg(all(windows, feature = "clipboard-win"))]
pub mod win32 {
    use super::{ClipboardError, HostClipboard, MAX_CLIPBOARD_PASTE_UTF8_BYTES};
    use std::ffi::OsStr;
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    use windows::Win32::Foundation::{GlobalFree, HANDLE, HGLOBAL};
    use windows::Win32::System::DataExchange::{
        CloseClipboard, EmptyClipboard, GetClipboardData, IsClipboardFormatAvailable, OpenClipboard,
        SetClipboardData,
    };
    use windows::Win32::System::Memory::{
        GlobalAlloc, GlobalLock, GlobalSize, GlobalUnlock, GMEM_MOVEABLE,
    };
    use windows::Win32::System::Ole::CF_UNICODETEXT;

    /// `CF_UNICODETEXT` as the `u32` format id expected by clipboard APIs.
    const FORMAT_UNICODETEXT: u32 = CF_UNICODETEXT.0 as u32;

    /// Host clipboard backed by Win32 `CF_UNICODETEXT`.
    ///
    /// Soft-fail stub for bridge wiring — clipboard errors must never tear down
    /// a session (C# `TerminalBridge` logs and cancels paste only). Error strings
    /// and `Debug` never include clipboard body text.
    #[derive(Debug, Default, Clone, Copy)]
    pub struct Win32Clipboard;

    impl HostClipboard for Win32Clipboard {
        fn read_text(&mut self) -> Result<String, ClipboardError> {
            read_unicode_text()
        }

        fn write_text(&mut self, text: &str) -> Result<(), ClipboardError> {
            write_unicode_text(text)
        }
    }

    fn read_unicode_text() -> Result<String, ClipboardError> {
        unsafe {
            if IsClipboardFormatAvailable(FORMAT_UNICODETEXT).is_err() {
                return Err(ClipboardError::Empty);
            }
            OpenClipboard(None).map_err(map_win_err("OpenClipboard"))?;
            let result = (|| {
                let handle = GetClipboardData(FORMAT_UNICODETEXT)
                    .map_err(map_win_err("GetClipboardData"))?;
                if handle.0.is_null() {
                    return Err(ClipboardError::Empty);
                }
                let hglobal = HGLOBAL(handle.0);
                let ptr = GlobalLock(hglobal);
                if ptr.is_null() {
                    return Err(ClipboardError::Failed("GlobalLock failed".into()));
                }
                // Bound reads to the HGLOBAL so a missing NUL cannot walk off
                // the allocation. `max_units = min(cap, avail-1)` leaves one
                // in-bounds unit for the fail-closed oversize/NUL peek.
                let avail_units = GlobalSize(hglobal) / std::mem::size_of::<u16>();
                let text = if avail_units == 0 {
                    Err(ClipboardError::Empty)
                } else {
                    let max_units = MAX_CLIPBOARD_PASTE_UTF8_BYTES.min(avail_units - 1);
                    nul_terminated_u16(ptr.cast::<u16>(), max_units).and_then(utf16_paste_to_string)
                };
                let _ = GlobalUnlock(hglobal);
                text
            })();
            let _ = CloseClipboard();
            result
        }
    }

    /// Decode UTF-16 clipboard units to UTF-8, fail-closed on the paste byte cap.
    ///
    /// Unit-count or decoded UTF-8 over the cap both become
    /// [`ClipboardError::TooLarge`] — never a truncated paste.
    fn utf16_paste_to_string(wide: &[u16]) -> Result<String, ClipboardError> {
        if wide.len() > MAX_CLIPBOARD_PASTE_UTF8_BYTES {
            return Err(ClipboardError::TooLarge {
                actual: wide.len(),
                limit: MAX_CLIPBOARD_PASTE_UTF8_BYTES,
            });
        }
        let text = std::ffi::OsString::from_wide(wide)
            .to_string_lossy()
            .into_owned();
        if text.len() > MAX_CLIPBOARD_PASTE_UTF8_BYTES {
            return Err(ClipboardError::TooLarge {
                actual: text.len(),
                limit: MAX_CLIPBOARD_PASTE_UTF8_BYTES,
            });
        }
        Ok(text)
    }

    fn write_unicode_text(text: &str) -> Result<(), ClipboardError> {
        let mut wide: Vec<u16> = OsStr::new(text).encode_wide().collect();
        wide.push(0);
        let bytes = wide.len() * std::mem::size_of::<u16>();
        unsafe {
            OpenClipboard(None).map_err(map_win_err("OpenClipboard"))?;
            let result = (|| {
                EmptyClipboard().map_err(map_win_err("EmptyClipboard"))?;
                let hglobal =
                    GlobalAlloc(GMEM_MOVEABLE, bytes).map_err(map_win_err("GlobalAlloc"))?;
                let ptr = GlobalLock(hglobal);
                if ptr.is_null() {
                    let _ = GlobalFree(Some(hglobal));
                    return Err(ClipboardError::Failed("GlobalLock failed".into()));
                }
                std::ptr::copy_nonoverlapping(wide.as_ptr(), ptr.cast::<u16>(), wide.len());
                let _ = GlobalUnlock(hglobal);
                match SetClipboardData(FORMAT_UNICODETEXT, Some(HANDLE(hglobal.0))) {
                    Ok(_) => {
                        // Ownership of hglobal transferred to the clipboard.
                        Ok(())
                    }
                    Err(e) => {
                        let _ = GlobalFree(Some(hglobal));
                        Err(map_win_err("SetClipboardData")(e))
                    }
                }
            })();
            let _ = CloseClipboard();
            result
        }
    }

    fn map_win_err(op: &'static str) -> impl Fn(windows::core::Error) -> ClipboardError {
        // Format must never include clipboard body — only the Win32 op + code.
        move |e| ClipboardError::Failed(format!("{op}: {e}"))
    }

    /// # Safety
    /// `ptr` must point to a readable UTF-16 buffer covering either a NUL within
    /// `max_units` units, or `max_units + 1` units when the first `max_units` are
    /// non-NUL (so the fail-closed peek at `ptr[max_units]` is defined). The
    /// returned slice is only valid while the caller holds `GlobalLock`.
    ///
    /// If the window fills without a terminating NUL at `ptr[max_units]`, returns
    /// [`ClipboardError::TooLarge`] instead of truncating.
    unsafe fn nul_terminated_u16<'a>(
        ptr: *const u16,
        max_units: usize,
    ) -> Result<&'a [u16], ClipboardError> {
        // SAFETY: caller guarantees the read bounds described above.
        unsafe {
            let mut len = 0usize;
            while len < max_units && *ptr.add(len) != 0 {
                len += 1;
            }
            if len == max_units && *ptr.add(len) != 0 {
                return Err(ClipboardError::TooLarge {
                    actual: max_units.saturating_add(1),
                    limit: MAX_CLIPBOARD_PASTE_UTF8_BYTES,
                });
            }
            Ok(std::slice::from_raw_parts(ptr, len))
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn utf16_paste_to_string_allows_exact_max_units_ascii() {
            let wide: Vec<u16> = std::iter::repeat_n(b'x' as u16, MAX_CLIPBOARD_PASTE_UTF8_BYTES)
                .collect();
            let text = utf16_paste_to_string(&wide).unwrap();
            assert_eq!(text.len(), MAX_CLIPBOARD_PASTE_UTF8_BYTES);
        }

        #[test]
        fn utf16_paste_to_string_rejects_over_max_units() {
            let wide: Vec<u16> =
                std::iter::repeat_n(b'x' as u16, MAX_CLIPBOARD_PASTE_UTF8_BYTES + 1).collect();
            match utf16_paste_to_string(&wide) {
                Err(ClipboardError::TooLarge { actual, limit }) => {
                    assert_eq!(actual, MAX_CLIPBOARD_PASTE_UTF8_BYTES + 1);
                    assert_eq!(limit, MAX_CLIPBOARD_PASTE_UTF8_BYTES);
                }
                other => panic!("expected TooLarge, got {other:?}"),
            }
        }

        #[test]
        fn utf16_paste_to_string_rejects_utf8_oversize_multibyte() {
            // U+3042 'あ' is one UTF-16 unit but three UTF-8 bytes — enough
            // units under the unit cap still exceed the UTF-8 paste cap.
            let units = (MAX_CLIPBOARD_PASTE_UTF8_BYTES / 3) + 1;
            let wide: Vec<u16> = std::iter::repeat_n(0x3042u16, units).collect();
            assert!(wide.len() <= MAX_CLIPBOARD_PASTE_UTF8_BYTES);
            match utf16_paste_to_string(&wide) {
                Err(ClipboardError::TooLarge { actual, limit }) => {
                    assert!(actual > MAX_CLIPBOARD_PASTE_UTF8_BYTES);
                    assert_eq!(limit, MAX_CLIPBOARD_PASTE_UTF8_BYTES);
                    let msg = ClipboardError::TooLarge { actual, limit }.to_string();
                    assert!(!msg.contains('\u{3042}'));
                }
                other => panic!("expected TooLarge, got {other:?}"),
            }
        }

        #[test]
        fn nul_terminated_u16_fail_closed_without_nul_in_window() {
            let buf: [u16; 4] = [b'a' as u16, b'b' as u16, b'c' as u16, b'd' as u16];
            // max_units == 3 consumes a,b,c; peek at 'd' → TooLarge (not "abc").
            let err = unsafe { nul_terminated_u16(buf.as_ptr(), 3) }.unwrap_err();
            assert!(matches!(err, ClipboardError::TooLarge { .. }));
            let msg = err.to_string();
            // Sizes only — never the UTF-16 body as text.
            assert!(!msg.contains("abc"));
            assert!(msg.contains('4') || msg.contains("1048576"));
        }

        #[test]
        fn nul_terminated_u16_allows_exact_window_with_trailing_nul() {
            let buf: [u16; 4] = [b'a' as u16, b'b' as u16, b'c' as u16, 0];
            let wide = unsafe { nul_terminated_u16(buf.as_ptr(), 3) }.unwrap();
            assert_eq!(wide, [b'a' as u16, b'b' as u16, b'c' as u16]);
        }

        #[test]
        fn nul_terminated_u16_stops_at_nul() {
            let buf: [u16; 4] = [b'a' as u16, b'b' as u16, 0, b'x' as u16];
            let wide = unsafe { nul_terminated_u16(buf.as_ptr(), 4) }.unwrap();
            assert_eq!(wide, [b'a' as u16, b'b' as u16]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encode_message;

    #[test]
    fn fake_roundtrip_read_write() {
        let mut clip = FakeClipboard::new();
        assert_eq!(clip.read_text(), Err(ClipboardError::Empty));
        clip.write_text("hello").unwrap();
        assert_eq!(clip.read_text().unwrap(), "hello");
        assert_eq!(clip.peek().as_deref(), Some("hello"));
    }

    #[test]
    fn fake_debug_omits_body() {
        let clip = FakeClipboard::with_text("super-secret-token");
        let dbg = format!("{clip:?}");
        assert!(dbg.contains("FakeClipboard"));
        assert!(!dbg.contains("super-secret"));
        assert!(dbg.contains("utf8_len"));
    }

    #[test]
    fn read_paste_text_enforces_cap() {
        let mut clip = FakeClipboard::with_text("ok");
        assert_eq!(read_paste_text(&mut clip).unwrap(), "ok");

        let huge = "x".repeat(MAX_CLIPBOARD_PASTE_UTF8_BYTES + 1);
        let mut clip = FakeClipboard::with_text(huge);
        match read_paste_text(&mut clip) {
            Err(ClipboardError::TooLarge { actual, limit }) => {
                assert_eq!(actual, MAX_CLIPBOARD_PASTE_UTF8_BYTES + 1);
                assert_eq!(limit, MAX_CLIPBOARD_PASTE_UTF8_BYTES);
            }
            other => panic!("expected TooLarge, got {other:?}"),
        }
    }

    #[test]
    fn read_paste_text_empty_string_is_empty_error() {
        // C# `IsNullOrEmpty` skips PostClipboardPasteInChunks for empty clipboard text.
        let mut clip = FakeClipboard::with_text("");
        assert_eq!(read_paste_text(&mut clip), Err(ClipboardError::Empty));
    }

    #[test]
    fn read_paste_text_allows_exact_max_bytes() {
        let exact = "x".repeat(MAX_CLIPBOARD_PASTE_UTF8_BYTES);
        let mut clip = FakeClipboard::with_text(exact.clone());
        assert_eq!(read_paste_text(&mut clip).unwrap(), exact);
    }

    #[test]
    fn build_paste_transaction_empty() {
        let frames = build_paste_transaction(7, false, "").unwrap();
        assert_eq!(frames.len(), 2);
        match &frames[0] {
            TerminalMessage::Clipboard(ClipboardHook::PasteBegin {
                request_id,
                force,
                total_utf8_bytes,
            }) => {
                assert_eq!(*request_id, 7);
                assert!(!*force);
                assert_eq!(*total_utf8_bytes, 0);
            }
            other => panic!("unexpected {other:?}"),
        }
        assert!(matches!(
            frames[1],
            TerminalMessage::Clipboard(ClipboardHook::PasteEnd { request_id: 7 })
        ));
    }

    #[test]
    fn build_paste_transaction_chunks_and_encodes() {
        let text: String = "あ".repeat(CLIPBOARD_PASTE_CHUNK_CHARS + 3);
        let frames = build_paste_transaction(1, true, &text).unwrap();
        // begin + 2 chunks + end
        assert_eq!(frames.len(), 4);
        let wire = encode_message(&frames[1]).unwrap();
        assert!(wire.starts_with("paste-chunk:1:"));
        // Never assert on decoded secret body in logs — just round-trip length.
        match &frames[1] {
            TerminalMessage::Clipboard(ClipboardHook::PasteChunk { data, .. }) => {
                assert_eq!(data.len(), "あ".len() * CLIPBOARD_PASTE_CHUNK_CHARS);
            }
            other => panic!("{other:?}"),
        }
        match &frames[2] {
            TerminalMessage::Clipboard(ClipboardHook::PasteChunk { data, .. }) => {
                assert_eq!(data.len(), "あ".len() * 3);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn build_paste_transaction_multi_chunk_ascii() {
        let text = "a".repeat(CLIPBOARD_PASTE_CHUNK_CHARS * 2 + 1);
        let frames = build_paste_transaction(3, false, &text).unwrap();
        // begin + 3 chunks + end
        assert_eq!(frames.len(), 5);
        match &frames[0] {
            TerminalMessage::Clipboard(ClipboardHook::PasteBegin {
                total_utf8_bytes, ..
            }) => {
                assert_eq!(*total_utf8_bytes, text.len() as u64);
            }
            other => panic!("{other:?}"),
        }
        let mut reassembled = String::new();
        for frame in &frames[1..frames.len() - 1] {
            match frame {
                TerminalMessage::Clipboard(ClipboardHook::PasteChunk { data, .. }) => {
                    assert!(!data.is_empty());
                    assert!(data.len() <= CLIPBOARD_PASTE_CHUNK_CHARS);
                    reassembled.push_str(std::str::from_utf8(data).unwrap());
                }
                other => panic!("expected PasteChunk, got {other:?}"),
            }
        }
        assert_eq!(reassembled, text);
        assert!(matches!(
            frames[frames.len() - 1],
            TerminalMessage::Clipboard(ClipboardHook::PasteEnd { request_id: 3 })
        ));
    }

    #[test]
    fn build_paste_transaction_exact_max_is_soft_ok() {
        let exact = "y".repeat(MAX_CLIPBOARD_PASTE_UTF8_BYTES);
        let frames = build_paste_transaction(2, false, &exact).unwrap();
        match &frames[0] {
            TerminalMessage::Clipboard(ClipboardHook::PasteBegin {
                total_utf8_bytes, ..
            }) => {
                assert_eq!(*total_utf8_bytes, MAX_CLIPBOARD_PASTE_UTF8_BYTES as u64);
            }
            other => panic!("{other:?}"),
        }
        assert!(frames.len() >= 3); // begin + ≥1 chunk + end
    }

    #[test]
    fn host_clipboard_trait_object_works() {
        let mut clip: Box<dyn HostClipboard> = Box::new(FakeClipboard::with_text("x"));
        assert_eq!(clip.read_text().unwrap(), "x");
        clip.write_text("y").unwrap();
        assert_eq!(clip.read_text().unwrap(), "y");
    }

    #[test]
    fn paste_chunk_size_matches_csharp() {
        assert_eq!(CLIPBOARD_PASTE_CHUNK_CHARS, 16 * 1024);
    }

    #[test]
    fn build_paste_transaction_rejects_oversize_without_emitting_body() {
        let huge = "x".repeat(MAX_CLIPBOARD_PASTE_UTF8_BYTES + 1);
        let err = build_paste_transaction(9, false, &huge).unwrap_err();
        let msg = err.to_string();
        assert!(matches!(err, ClipboardError::TooLarge { .. }));
        // Error text carries sizes only — never the paste body.
        assert!(!msg.contains("xxxxx"));
        assert!(msg.contains(&(MAX_CLIPBOARD_PASTE_UTF8_BYTES + 1).to_string()));
    }

    #[test]
    fn clipboard_error_display_omits_bodies() {
        let err = ClipboardError::Failed("OpenClipboard: access denied".into());
        let msg = err.to_string();
        assert!(msg.contains("OpenClipboard"));
        assert!(!msg.contains("secret"));
    }

    #[test]
    fn paste_chunk_debug_redacts_body() {
        let hook = ClipboardHook::PasteChunk {
            request_id: 1,
            data: Bytes::from_static(b"super-secret-paste-body"),
        };
        let dbg = format!("{hook:?}");
        assert!(dbg.contains("utf8_len"));
        assert!(!dbg.contains("super-secret"));
    }

    #[test]
    fn selection_copy_debug_redacts_body() {
        let hook = ClipboardHook::SelectionCopy {
            data: Bytes::from_static(b"super-secret-selection"),
        };
        let dbg = format!("{hook:?}");
        assert!(dbg.contains("utf8_len"));
        assert!(!dbg.contains("super-secret"));
    }

    #[test]
    fn terminal_message_clipboard_debug_redacts_paste_body() {
        let msg = TerminalMessage::Clipboard(ClipboardHook::PasteChunk {
            request_id: 42,
            data: Bytes::from_static(b"super-secret-via-terminal-message"),
        });
        let dbg = format!("{msg:?}");
        assert!(dbg.contains("PasteChunk"));
        assert!(dbg.contains("utf8_len"));
        assert!(!dbg.contains("super-secret"));
    }

    #[test]
    fn utf8_char_chunks_split_on_scalar_boundaries() {
        let text = "a😀b";
        let chunks: Vec<&str> = utf8_char_chunks(text, 2).collect();
        assert_eq!(chunks, vec!["a😀", "b"]);
    }

    #[test]
    fn utf8_char_chunks_zero_max_yields_nothing() {
        assert!(utf8_char_chunks("abc", 0).next().is_none());
        assert!(utf8_char_chunks("", 8).next().is_none());
    }

    #[test]
    fn utf8_char_chunks_keeps_crlf_together() {
        // Without the CRLF guard, max_chars=3 on "ab\r\ncd" would emit "ab\r" | "\ncd".
        // C# decrements characterCount so the pair stays together.
        let text = "ab\r\ncd";
        let chunks: Vec<&str> = utf8_char_chunks(text, 3).collect();
        assert_eq!(chunks.concat(), text);
        assert_eq!(chunks, vec!["ab", "\r\nc", "d"]);
        assert!(
            !chunks
                .windows(2)
                .any(|w| w[0].ends_with('\r') && w[1].starts_with('\n')),
            "CRLF must not straddle chunk boundary: {chunks:?}"
        );
    }

    #[test]
    fn utf8_char_chunks_crlf_at_max_chars_one_takes_pair() {
        // max_chars == 1 ending on CR would empty the window if we only pull back;
        // take the whole CRLF instead (progress + keep pair).
        let chunks: Vec<&str> = utf8_char_chunks("\r\nx", 1).collect();
        assert_eq!(chunks, vec!["\r\n", "x"]);
    }

    #[test]
    fn utf8_char_chunks_never_emits_empty() {
        for max in [1usize, 2, 3, 8, CLIPBOARD_PASTE_CHUNK_CHARS] {
            for chunk in utf8_char_chunks("a\r\nb\r\nc", max) {
                assert!(!chunk.is_empty(), "empty chunk at max_chars={max}");
            }
        }
    }

    #[test]
    fn build_paste_transaction_keeps_crlf_at_production_chunk_boundary() {
        // Place CRLF exactly where a naive max_chars window would split it.
        let mut text = "a".repeat(CLIPBOARD_PASTE_CHUNK_CHARS - 1);
        text.push_str("\r\nb");
        let frames = build_paste_transaction(11, false, &text).unwrap();
        let mut chunks = Vec::new();
        for frame in &frames[1..frames.len() - 1] {
            match frame {
                TerminalMessage::Clipboard(ClipboardHook::PasteChunk { data, .. }) => {
                    chunks.push(std::str::from_utf8(data).unwrap().to_string());
                }
                other => panic!("expected PasteChunk, got {other:?}"),
            }
        }
        assert_eq!(chunks.concat(), text);
        assert!(
            !chunks
                .windows(2)
                .any(|w| w[0].ends_with('\r') && w[1].starts_with('\n')),
            "CRLF must not straddle production chunks: {chunks:?}"
        );
        // Debug of the full frame list must not leak paste body.
        let dbg = format!("{frames:?}");
        assert!(!dbg.contains("\r\nb"));
        assert!(!dbg.contains(&"a".repeat(32)));
    }

    #[test]
    fn lone_cr_may_end_a_chunk() {
        // CRLF guard is pair-only; a lone CR at the window edge is fine.
        let chunks: Vec<&str> = utf8_char_chunks("ab\rcd", 3).collect();
        assert_eq!(chunks, vec!["ab\r", "cd"]);
    }

    #[cfg(all(windows, feature = "clipboard-win"))]
    #[test]
    fn win32_clipboard_is_available_with_feature() {
        use super::win32::Win32Clipboard;
        let mut clip = Win32Clipboard;
        // Soft-fail only — do not assert OS clipboard contents in CI.
        let _ = clip.read_text();
        let dbg = format!("{clip:?}");
        assert!(dbg.contains("Win32Clipboard"));
    }

    #[cfg(not(feature = "clipboard-win"))]
    #[test]
    fn default_build_exposes_fake_not_win32_module_path() {
        // `clipboard-win` is off by default; FakeClipboard remains the test host.
        let clip = FakeClipboard::new();
        assert!(clip.peek().is_none());
        assert_eq!(CLIPBOARD_PASTE_CHUNK_CHARS, 16 * 1024);
    }
}
