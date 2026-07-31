//! xterm.js WebView2 bridge wire messages.
//!
//! Wire format matches `Interop/Terminal/TerminalBridgeMessages.cs` /
//! `Assets/web/bridge.js`:
//! - host→page output: `d:<stream>:<frame>:<base64>`
//! - host→page replay: `q:<stream>:<frame>:<base64>`
//! - host→page focus / parser / retirement: `f:` / `k:` / `x:` + stream
//! - host→page clear: `clear:` or `clear:<stream>`
//! - host→page paste-drain / paste-begin / paste-chunk / paste-end / paste-cancel
//! - page→host ack: `a:<stream>:<frame>`
//! - page→host input: `b:<stream>:<u|p>:<base64>`
//! - page→host resize: `r:<stream>:<cols>x<rows>`
//! - page→host paste request: `p:<requestId>:<0|1>`
//! - page→host selection copy: `c:<base64>`
//! - page→host ready / focus / barrier / error / fatal / collapsed-fit
//!
//! Size caps mirror `TerminalBridge.cs` constants so a hostile WebView cannot
//! force unbounded decode allocations through the message codec alone.

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use bytes::Bytes;

use crate::error::TerminalError;
use crate::Result;

/// Max host→page output/replay frame payload (`TerminalBridge.MaxFrameBytes`).
pub const MAX_OUTPUT_FRAME_BYTES: usize = 128 * 1024;
/// Max page→host input payload (`MaximumInputFrameUtf8Bytes`).
pub const MAX_INPUT_FRAME_UTF8_BYTES: usize = 1024 * 1024 + 64;
/// Max clipboard paste transaction size (`MaximumClipboardPasteUtf8Bytes`).
pub const MAX_CLIPBOARD_PASTE_UTF8_BYTES: usize = 1024 * 1024;
/// Max selection-copy payload (`MaximumSelectionUtf8Bytes`).
pub const MAX_SELECTION_UTF8_BYTES: usize = 4 * 1024 * 1024;
/// Absolute wire-string cap (`MaximumPendingWebMessageCharacters`).
pub const MAX_WIRE_CHARS: usize = 8 * 1024 * 1024;
/// Default minimum usable columns (`TerminalBridge.MinimumUsableColumns`).
pub const MIN_USABLE_COLUMNS: u32 = 20;
/// Default minimum usable rows (`TerminalBridge.MinimumUsableRows`).
pub const MIN_USABLE_ROWS: u32 = 8;
/// Truncate hostile wire bodies embedded in error strings.
const ERROR_WIRE_PREVIEW_CHARS: usize = 128;

/// Input origin on `b:` frames (user keystrokes vs xterm parser replies).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InputOrigin {
    User,
    Parser,
}

impl InputOrigin {
    fn wire(self) -> char {
        match self {
            Self::User => 'u',
            Self::Parser => 'p',
        }
    }

    fn parse(c: char) -> Option<Self> {
        match c {
            'u' => Some(Self::User),
            'p' => Some(Self::Parser),
            _ => None,
        }
    }
}

/// Clipboard-related bridge hooks (paste request / selection copy / paste delivery).
///
/// `Debug` redacts paste / selection bodies (length only) so accidental logging
/// cannot leak clipboard text.
#[derive(Clone, PartialEq, Eq)]
pub enum ClipboardHook {
    /// Page asks native to read the clipboard (`p:<id>:<force>`).
    PasteRequest { request_id: i64, force: bool },
    /// Page sends selected text for native clipboard write (`c:<base64>`).
    SelectionCopy { data: Bytes },
    /// Native releases the JS paste gate (`paste-drain:<id>`).
    PasteDrain { request_id: i64 },
    /// Native starts a paste transaction (`paste-begin:<id>:<force>:<utf8Bytes>`).
    PasteBegin {
        request_id: i64,
        force: bool,
        total_utf8_bytes: u64,
    },
    /// Native paste chunk (`paste-chunk:<id>:<base64>`).
    PasteChunk { request_id: i64, data: Bytes },
    /// Native paste finished (`paste-end:<id>`).
    PasteEnd { request_id: i64 },
    /// Native cancelled paste (`paste-cancel:<id>`).
    PasteCancel { request_id: i64 },
}

impl std::fmt::Debug for ClipboardHook {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PasteRequest { request_id, force } => f
                .debug_struct("PasteRequest")
                .field("request_id", request_id)
                .field("force", force)
                .finish(),
            Self::SelectionCopy { data } => f
                .debug_struct("SelectionCopy")
                .field("utf8_len", &data.len())
                .finish(),
            Self::PasteDrain { request_id } => f
                .debug_struct("PasteDrain")
                .field("request_id", request_id)
                .finish(),
            Self::PasteBegin {
                request_id,
                force,
                total_utf8_bytes,
            } => f
                .debug_struct("PasteBegin")
                .field("request_id", request_id)
                .field("force", force)
                .field("total_utf8_bytes", total_utf8_bytes)
                .finish(),
            Self::PasteChunk { request_id, data } => f
                .debug_struct("PasteChunk")
                .field("request_id", request_id)
                .field("utf8_len", &data.len())
                .finish(),
            Self::PasteEnd { request_id } => f
                .debug_struct("PasteEnd")
                .field("request_id", request_id)
                .finish(),
            Self::PasteCancel { request_id } => f
                .debug_struct("PasteCancel")
                .field("request_id", request_id)
                .finish(),
        }
    }
}

/// Disposition for sessionless replay completion frames (C# classify helper).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SessionlessReplayDisposition {
    Ignore,
    Ready,
    CurrentFailure,
    RecoverableFatal,
}

/// Bidirectional terminal bridge message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TerminalMessage {
    /// Host → page live output (`d:`).
    Output {
        stream_id: i64,
        frame_id: i64,
        data: Bytes,
    },
    /// Host → page replay (`q:`).
    Replay {
        stream_id: i64,
        frame_id: i64,
        data: Bytes,
    },
    /// Host → page ordered focus barrier (`f:<stream>`).
    FocusBarrier { stream_id: i64 },
    /// Host → page neutral parser barrier (`k:<stream>`).
    ParserBarrier { stream_id: i64 },
    /// Host → page retirement boundary (`x:<stream>`).
    Retirement { stream_id: i64 },
    /// Host → page ordered clear (`clear:` or `clear:<stream>`).
    Clear { stream_id: Option<i64> },
    /// Page → host output ACK (`a:`).
    OutputAck { stream_id: i64, frame_id: i64 },
    /// Page → host keystroke / parser reply (`b:`).
    Input {
        stream_id: i64,
        origin: InputOrigin,
        data: Bytes,
    },
    /// Page → host geometry (`r:`).
    Resize {
        stream_id: i64,
        columns: u32,
        rows: u32,
    },
    /// Page → host one-shot handshake (`ready:COLSxROWS`).
    Ready { columns: u32, rows: u32 },
    /// Page → host init failure (`error:…`).
    PageError { detail: String },
    /// Page → host collapsed-fit diagnostic (`z:collapsed-fit:…`).
    CollapsedFit { detail: String },
    /// Page → host: parser barrier ready (`barrier:<stream>`).
    ParserBarrierReady { stream_id: i64 },
    /// Page → host: focus ready (`focus:<stream>`).
    FocusReady { stream_id: i64 },
    /// Page → host: output write failure (`fatal:write:<stream>:<frame>`).
    OutputWriteFailure { stream_id: i64, frame_id: i64 },
    /// Page → host: barrier failure (`fatal:barrier:<stream>`).
    ParserBarrierFailure { stream_id: i64 },
    /// Page → host: clear failure (`fatal:clear:<stream>`).
    TerminalClearFailure { stream_id: i64 },
    /// Page → host: other fatal frame (`fatal:…`).
    PageFatal { detail: String },
    /// Clipboard hook envelope.
    Clipboard(ClipboardHook),
}

/// True when the wire string is any page fatal frame (`fatal:` prefix).
pub fn is_page_fatal_frame(wire: &str) -> bool {
    wire.starts_with("fatal:")
}

/// Classify a page→host frame during sessionless replay (C# parity).
///
/// `current_stream_id` must be `> 0` (same precondition as the C# helper).
pub fn classify_sessionless_replay_message(
    wire: &str,
    current_stream_id: i64,
) -> Result<SessionlessReplayDisposition> {
    if current_stream_id <= 0 {
        return Err(TerminalError::InvalidMessage(
            "current_stream_id must be > 0".into(),
        ));
    }

    // Decode once — hostile wires can be up to MAX_WIRE_CHARS.
    Ok(match decode_message(wire) {
        Ok(TerminalMessage::ParserBarrierReady { stream_id }) => {
            if stream_id == current_stream_id {
                SessionlessReplayDisposition::Ready
            } else {
                SessionlessReplayDisposition::Ignore
            }
        }
        Ok(TerminalMessage::OutputWriteFailure { stream_id, .. })
        | Ok(TerminalMessage::ParserBarrierFailure { stream_id })
        | Ok(TerminalMessage::TerminalClearFailure { stream_id }) => {
            if stream_id == current_stream_id {
                SessionlessReplayDisposition::CurrentFailure
            } else {
                // Typed fatal for another stream still carries a `fatal:` prefix.
                SessionlessReplayDisposition::RecoverableFatal
            }
        }
        Ok(_) | Err(_) => {
            // Includes PageFatal and malformed `fatal:…` (e.g. `fatal:write:42:0`).
            if is_page_fatal_frame(wire) {
                SessionlessReplayDisposition::RecoverableFatal
            } else {
                SessionlessReplayDisposition::Ignore
            }
        }
    })
}

/// C# `TryParseScopedGeometry` parity — usable resize only.
///
/// Returns `None` for non-resize frames, malformed wire, or geometry below the
/// supplied minimums (callers typically pass [`MIN_USABLE_COLUMNS`] /
/// [`MIN_USABLE_ROWS`]).
pub fn try_parse_scoped_geometry(
    wire: &str,
    minimum_columns: u32,
    minimum_rows: u32,
) -> Option<(i64, u32, u32)> {
    match decode_message(wire) {
        Ok(TerminalMessage::Resize {
            stream_id,
            columns,
            rows,
        }) if columns >= minimum_columns && rows >= minimum_rows => {
            Some((stream_id, columns, rows))
        }
        _ => None,
    }
}

/// Encode a message to the WebView2 string wire format.
pub fn encode_message(message: &TerminalMessage) -> Result<String> {
    match message {
        TerminalMessage::Output {
            stream_id,
            frame_id,
            data,
        } => encode_framed('d', *stream_id, *frame_id, data),
        TerminalMessage::Replay {
            stream_id,
            frame_id,
            data,
        } => encode_framed('q', *stream_id, *frame_id, data),
        TerminalMessage::FocusBarrier { stream_id } => {
            require_positive(*stream_id, "stream_id")?;
            Ok(format!("f:{stream_id}"))
        }
        TerminalMessage::ParserBarrier { stream_id } => {
            require_positive(*stream_id, "stream_id")?;
            Ok(format!("k:{stream_id}"))
        }
        TerminalMessage::Retirement { stream_id } => {
            require_positive(*stream_id, "stream_id")?;
            Ok(format!("x:{stream_id}"))
        }
        TerminalMessage::Clear { stream_id } => match stream_id {
            None => Ok("clear:".into()),
            Some(id) => {
                require_positive(*id, "stream_id")?;
                Ok(format!("clear:{id}"))
            }
        },
        TerminalMessage::OutputAck {
            stream_id,
            frame_id,
        } => {
            require_positive(*stream_id, "stream_id")?;
            require_positive(*frame_id, "frame_id")?;
            Ok(format!("a:{stream_id}:{frame_id}"))
        }
        TerminalMessage::Input {
            stream_id,
            origin,
            data,
        } => {
            require_positive(*stream_id, "stream_id")?;
            if data.is_empty() {
                return Err(TerminalError::EmptyPayload);
            }
            require_payload_limit("input", data.len(), MAX_INPUT_FRAME_UTF8_BYTES)?;
            Ok(format!(
                "b:{stream_id}:{}:{}",
                origin.wire(),
                B64.encode(data)
            ))
        }
        TerminalMessage::Resize {
            stream_id,
            columns,
            rows,
        } => {
            require_positive(*stream_id, "stream_id")?;
            if *columns == 0 || *rows == 0 {
                return Err(TerminalError::InvalidMessage(
                    "resize columns/rows must be > 0".into(),
                ));
            }
            Ok(format!("r:{stream_id}:{columns}x{rows}"))
        }
        TerminalMessage::Ready { columns, rows } => {
            if *columns == 0 || *rows == 0 {
                return Err(TerminalError::InvalidMessage(
                    "ready columns/rows must be > 0".into(),
                ));
            }
            Ok(format!("ready:{columns}x{rows}"))
        }
        TerminalMessage::PageError { detail } => {
            if detail.is_empty() {
                return Err(TerminalError::InvalidMessage(
                    "page error detail must be non-empty".into(),
                ));
            }
            let wire = format!("error:{detail}");
            if wire.len() > MAX_WIRE_CHARS {
                return Err(TerminalError::MessageTooLarge {
                    kind: "wire",
                    actual: wire.len(),
                    limit: MAX_WIRE_CHARS,
                });
            }
            Ok(wire)
        }
        TerminalMessage::CollapsedFit { detail } => {
            let wire = format!("z:collapsed-fit:{detail}");
            if wire.len() > MAX_WIRE_CHARS {
                return Err(TerminalError::MessageTooLarge {
                    kind: "wire",
                    actual: wire.len(),
                    limit: MAX_WIRE_CHARS,
                });
            }
            Ok(wire)
        }
        TerminalMessage::ParserBarrierReady { stream_id } => {
            require_positive(*stream_id, "stream_id")?;
            Ok(format!("barrier:{stream_id}"))
        }
        TerminalMessage::FocusReady { stream_id } => {
            require_positive(*stream_id, "stream_id")?;
            Ok(format!("focus:{stream_id}"))
        }
        TerminalMessage::OutputWriteFailure {
            stream_id,
            frame_id,
        } => {
            require_positive(*stream_id, "stream_id")?;
            require_positive(*frame_id, "frame_id")?;
            Ok(format!("fatal:write:{stream_id}:{frame_id}"))
        }
        TerminalMessage::ParserBarrierFailure { stream_id } => {
            require_positive(*stream_id, "stream_id")?;
            Ok(format!("fatal:barrier:{stream_id}"))
        }
        TerminalMessage::TerminalClearFailure { stream_id } => {
            require_positive(*stream_id, "stream_id")?;
            Ok(format!("fatal:clear:{stream_id}"))
        }
        TerminalMessage::PageFatal { detail } => {
            if detail.is_empty() {
                return Err(TerminalError::InvalidMessage(
                    "page fatal detail must be non-empty".into(),
                ));
            }
            // `detail` is the suffix after `fatal:` (e.g. `protocol`), matching decode.
            let wire = if let Some(rest) = detail.strip_prefix("fatal:") {
                format!("fatal:{rest}")
            } else {
                format!("fatal:{detail}")
            };
            if wire.len() > MAX_WIRE_CHARS {
                return Err(TerminalError::MessageTooLarge {
                    kind: "wire",
                    actual: wire.len(),
                    limit: MAX_WIRE_CHARS,
                });
            }
            Ok(wire)
        }
        TerminalMessage::Clipboard(hook) => encode_clipboard(hook),
    }
}

/// Decode a wire string into a [`TerminalMessage`].
pub fn decode_message(wire: &str) -> Result<TerminalMessage> {
    if wire.len() > MAX_WIRE_CHARS {
        return Err(TerminalError::MessageTooLarge {
            kind: "wire",
            actual: wire.len(),
            limit: MAX_WIRE_CHARS,
        });
    }

    if let Some(rest) = wire.strip_prefix("d:") {
        let (stream_id, frame_id, data) = decode_framed(rest, MAX_OUTPUT_FRAME_BYTES)?;
        return Ok(TerminalMessage::Output {
            stream_id,
            frame_id,
            data,
        });
    }
    if let Some(rest) = wire.strip_prefix("q:") {
        let (stream_id, frame_id, data) = decode_framed(rest, MAX_OUTPUT_FRAME_BYTES)?;
        return Ok(TerminalMessage::Replay {
            stream_id,
            frame_id,
            data,
        });
    }
    if let Some(rest) = wire.strip_prefix("f:") {
        return Ok(TerminalMessage::FocusBarrier {
            stream_id: parse_positive_i64(rest)?,
        });
    }
    if let Some(rest) = wire.strip_prefix("k:") {
        return Ok(TerminalMessage::ParserBarrier {
            stream_id: parse_positive_i64(rest)?,
        });
    }
    if let Some(rest) = wire.strip_prefix("x:") {
        return Ok(TerminalMessage::Retirement {
            stream_id: parse_positive_i64(rest)?,
        });
    }
    if wire == "clear:" {
        return Ok(TerminalMessage::Clear { stream_id: None });
    }
    if let Some(rest) = wire.strip_prefix("clear:") {
        return Ok(TerminalMessage::Clear {
            stream_id: Some(parse_positive_i64(rest)?),
        });
    }
    if let Some(rest) = wire.strip_prefix("a:") {
        let (stream_id, frame_id) = parse_two_positive_i64(rest)?;
        return Ok(TerminalMessage::OutputAck {
            stream_id,
            frame_id,
        });
    }
    if let Some(rest) = wire.strip_prefix("b:") {
        return decode_input(rest);
    }
    if let Some(rest) = wire.strip_prefix("r:") {
        return decode_resize(rest);
    }
    if let Some(rest) = wire.strip_prefix("ready:") {
        return decode_ready(rest);
    }
    if let Some(rest) = wire.strip_prefix("error:") {
        if rest.is_empty() {
            return Err(invalid_message("empty error detail", wire));
        }
        return Ok(TerminalMessage::PageError {
            detail: rest.to_string(),
        });
    }
    if let Some(rest) = wire.strip_prefix("z:collapsed-fit:") {
        return Ok(TerminalMessage::CollapsedFit {
            detail: rest.to_string(),
        });
    }
    if let Some(rest) = wire.strip_prefix("barrier:") {
        return Ok(TerminalMessage::ParserBarrierReady {
            stream_id: parse_positive_i64(rest)?,
        });
    }
    if let Some(rest) = wire.strip_prefix("focus:") {
        return Ok(TerminalMessage::FocusReady {
            stream_id: parse_positive_i64(rest)?,
        });
    }
    if let Some(rest) = wire.strip_prefix("fatal:write:") {
        let (stream_id, frame_id) = parse_two_positive_i64(rest)?;
        return Ok(TerminalMessage::OutputWriteFailure {
            stream_id,
            frame_id,
        });
    }
    if let Some(rest) = wire.strip_prefix("fatal:barrier:") {
        return Ok(TerminalMessage::ParserBarrierFailure {
            stream_id: parse_positive_i64(rest)?,
        });
    }
    if let Some(rest) = wire.strip_prefix("fatal:clear:") {
        return Ok(TerminalMessage::TerminalClearFailure {
            stream_id: parse_positive_i64(rest)?,
        });
    }
    if let Some(detail) = wire.strip_prefix("fatal:") {
        if detail.is_empty() {
            return Err(invalid_message("empty fatal detail", wire));
        }
        return Ok(TerminalMessage::PageFatal {
            detail: detail.to_string(),
        });
    }
    if let Some(rest) = wire.strip_prefix("p:") {
        return decode_paste_request(rest);
    }
    if let Some(rest) = wire.strip_prefix("c:") {
        let data = decode_b64(rest)?;
        require_payload_limit("selection", data.len(), MAX_SELECTION_UTF8_BYTES)?;
        return Ok(TerminalMessage::Clipboard(ClipboardHook::SelectionCopy {
            data,
        }));
    }
    if let Some(rest) = wire.strip_prefix("paste-drain:") {
        return Ok(TerminalMessage::Clipboard(ClipboardHook::PasteDrain {
            request_id: parse_positive_i64(rest)?,
        }));
    }
    if let Some(rest) = wire.strip_prefix("paste-begin:") {
        return decode_paste_begin(rest);
    }
    if let Some(rest) = wire.strip_prefix("paste-chunk:") {
        return decode_paste_chunk(rest);
    }
    if let Some(rest) = wire.strip_prefix("paste-end:") {
        let request_id = parse_positive_i64(rest)?;
        return Ok(TerminalMessage::Clipboard(ClipboardHook::PasteEnd {
            request_id,
        }));
    }
    if let Some(rest) = wire.strip_prefix("paste-cancel:") {
        let request_id = parse_positive_i64(rest)?;
        return Ok(TerminalMessage::Clipboard(ClipboardHook::PasteCancel {
            request_id,
        }));
    }

    Err(invalid_message("unrecognized terminal frame", wire))
}

fn encode_clipboard(hook: &ClipboardHook) -> Result<String> {
    match hook {
        ClipboardHook::PasteRequest { request_id, force } => {
            require_positive(*request_id, "request_id")?;
            Ok(format!("p:{request_id}:{}", if *force { 1 } else { 0 }))
        }
        ClipboardHook::SelectionCopy { data } => {
            require_payload_limit("selection", data.len(), MAX_SELECTION_UTF8_BYTES)?;
            Ok(format!("c:{}", B64.encode(data)))
        }
        ClipboardHook::PasteDrain { request_id } => {
            require_positive(*request_id, "request_id")?;
            Ok(format!("paste-drain:{request_id}"))
        }
        ClipboardHook::PasteBegin {
            request_id,
            force,
            total_utf8_bytes,
        } => {
            require_positive(*request_id, "request_id")?;
            if *total_utf8_bytes > MAX_CLIPBOARD_PASTE_UTF8_BYTES as u64 {
                return Err(TerminalError::MessageTooLarge {
                    kind: "paste",
                    actual: *total_utf8_bytes as usize,
                    limit: MAX_CLIPBOARD_PASTE_UTF8_BYTES,
                });
            }
            Ok(format!(
                "paste-begin:{request_id}:{}:{total_utf8_bytes}",
                if *force { 1 } else { 0 }
            ))
        }
        ClipboardHook::PasteChunk { request_id, data } => {
            require_positive(*request_id, "request_id")?;
            require_payload_limit("paste-chunk", data.len(), MAX_CLIPBOARD_PASTE_UTF8_BYTES)?;
            Ok(format!("paste-chunk:{request_id}:{}", B64.encode(data)))
        }
        ClipboardHook::PasteEnd { request_id } => {
            require_positive(*request_id, "request_id")?;
            Ok(format!("paste-end:{request_id}"))
        }
        ClipboardHook::PasteCancel { request_id } => {
            require_positive(*request_id, "request_id")?;
            Ok(format!("paste-cancel:{request_id}"))
        }
    }
}

fn encode_framed(kind: char, stream_id: i64, frame_id: i64, data: &Bytes) -> Result<String> {
    require_positive(stream_id, "stream_id")?;
    require_positive(frame_id, "frame_id")?;
    if data.is_empty() {
        return Err(TerminalError::EmptyPayload);
    }
    require_payload_limit("output", data.len(), MAX_OUTPUT_FRAME_BYTES)?;
    Ok(format!(
        "{kind}:{stream_id}:{frame_id}:{}",
        B64.encode(data)
    ))
}

fn decode_framed(rest: &str, max_bytes: usize) -> Result<(i64, i64, Bytes)> {
    let (stream_txt, after_stream) = split_once(rest, ':')?;
    let (frame_txt, b64) = split_once(after_stream, ':')?;
    let stream_id = parse_positive_i64(stream_txt)?;
    let frame_id = parse_positive_i64(frame_txt)?;
    let data = decode_b64(b64)?;
    if data.is_empty() {
        return Err(TerminalError::EmptyPayload);
    }
    require_payload_limit("output", data.len(), max_bytes)?;
    Ok((stream_id, frame_id, data))
}

fn decode_input(rest: &str) -> Result<TerminalMessage> {
    let (stream_txt, after_stream) = split_once(rest, ':')?;
    let (origin_txt, b64) = split_once(after_stream, ':')?;
    if origin_txt.len() != 1 {
        return Err(TerminalError::InvalidMessage(
            "input origin must be a single char".into(),
        ));
    }
    let origin = InputOrigin::parse(origin_txt.chars().next().unwrap()).ok_or_else(|| {
        TerminalError::InvalidMessage(format!("unknown input origin '{origin_txt}'"))
    })?;
    // C# TryParseInputFrame requires a non-empty payload region and rejects ':' in it.
    if b64.is_empty() || b64.contains(':') {
        return Err(TerminalError::InvalidMessage(
            "input payload must be non-empty base64 without ':'".into(),
        ));
    }
    let stream_id = parse_positive_i64(stream_txt)?;
    let data = decode_b64(b64)?;
    if data.is_empty() {
        return Err(TerminalError::EmptyPayload);
    }
    require_payload_limit("input", data.len(), MAX_INPUT_FRAME_UTF8_BYTES)?;
    Ok(TerminalMessage::Input {
        stream_id,
        origin,
        data,
    })
}

fn decode_resize(rest: &str) -> Result<TerminalMessage> {
    let (stream_txt, size) = split_once(rest, ':')?;
    let (cols_txt, rows_txt) = split_once(size, 'x')?;
    let stream_id = parse_positive_i64(stream_txt)?;
    let columns = parse_canonical_u32(cols_txt)?;
    let rows = parse_canonical_u32(rows_txt)?;
    if columns == 0 || rows == 0 {
        return Err(TerminalError::InvalidMessage(
            "resize columns/rows must be > 0".into(),
        ));
    }
    Ok(TerminalMessage::Resize {
        stream_id,
        columns,
        rows,
    })
}

fn decode_ready(rest: &str) -> Result<TerminalMessage> {
    let (cols_txt, rows_txt) = split_once(rest, 'x')?;
    let columns = parse_canonical_u32(cols_txt)?;
    let rows = parse_canonical_u32(rows_txt)?;
    if columns == 0 || rows == 0 {
        return Err(TerminalError::InvalidMessage(
            "ready columns/rows must be > 0".into(),
        ));
    }
    Ok(TerminalMessage::Ready { columns, rows })
}

fn decode_paste_request(rest: &str) -> Result<TerminalMessage> {
    let (id_txt, force_txt) = split_once(rest, ':')?;
    if force_txt.len() != 1 || !matches!(force_txt.as_bytes()[0], b'0' | b'1') {
        return Err(TerminalError::InvalidMessage(
            "paste force flag must be 0 or 1".into(),
        ));
    }
    Ok(TerminalMessage::Clipboard(ClipboardHook::PasteRequest {
        request_id: parse_positive_i64(id_txt)?,
        force: force_txt.as_bytes()[0] == b'1',
    }))
}

fn decode_paste_begin(rest: &str) -> Result<TerminalMessage> {
    let (id_txt, after_id) = split_once(rest, ':')?;
    let (force_txt, bytes_txt) = split_once(after_id, ':')?;
    if force_txt.len() != 1 || !matches!(force_txt.as_bytes()[0], b'0' | b'1') {
        return Err(TerminalError::InvalidMessage(
            "paste-begin force flag must be 0 or 1".into(),
        ));
    }
    let total_utf8_bytes = parse_canonical_u64(bytes_txt)?;
    if total_utf8_bytes > MAX_CLIPBOARD_PASTE_UTF8_BYTES as u64 {
        return Err(TerminalError::MessageTooLarge {
            kind: "paste",
            actual: total_utf8_bytes as usize,
            limit: MAX_CLIPBOARD_PASTE_UTF8_BYTES,
        });
    }
    Ok(TerminalMessage::Clipboard(ClipboardHook::PasteBegin {
        request_id: parse_positive_i64(id_txt)?,
        force: force_txt.as_bytes()[0] == b'1',
        total_utf8_bytes,
    }))
}

fn decode_paste_chunk(rest: &str) -> Result<TerminalMessage> {
    let (id_txt, b64) = split_once(rest, ':')?;
    let data = decode_b64(b64)?;
    require_payload_limit("paste-chunk", data.len(), MAX_CLIPBOARD_PASTE_UTF8_BYTES)?;
    Ok(TerminalMessage::Clipboard(ClipboardHook::PasteChunk {
        request_id: parse_positive_i64(id_txt)?,
        data,
    }))
}

fn decode_b64(encoded: &str) -> Result<Bytes> {
    if encoded.is_empty() {
        return Ok(Bytes::new());
    }
    B64.decode(encoded.as_bytes())
        .map(Bytes::from)
        .map_err(|e| TerminalError::InvalidMessage(format!("invalid base64: {e}")))
}

fn split_once(s: &str, delim: char) -> Result<(&str, &str)> {
    s.split_once(delim)
        .ok_or_else(|| TerminalError::InvalidMessage(format!("missing '{delim}' separator")))
}

fn require_positive(value: i64, name: &str) -> Result<()> {
    if value <= 0 {
        Err(TerminalError::InvalidMessage(format!(
            "{name} must be > 0"
        )))
    } else {
        Ok(())
    }
}

fn require_payload_limit(kind: &'static str, actual: usize, limit: usize) -> Result<()> {
    if actual > limit {
        Err(TerminalError::MessageTooLarge {
            kind,
            actual,
            limit,
        })
    } else {
        Ok(())
    }
}

fn parse_positive_i64(text: &str) -> Result<i64> {
    ensure_canonical_unsigned_text(text)?;
    let parsed: i64 = text
        .parse()
        .map_err(|_| TerminalError::InvalidMessage(format!("invalid integer '{text}'")))?;
    if parsed <= 0 {
        return Err(TerminalError::InvalidMessage(format!(
            "integer must be > 0, got {parsed}"
        )));
    }
    Ok(parsed)
}

fn parse_canonical_u32(text: &str) -> Result<u32> {
    ensure_canonical_unsigned_text(text)?;
    text.parse()
        .map_err(|_| TerminalError::InvalidMessage(format!("invalid u32 '{text}'")))
}

fn parse_canonical_u64(text: &str) -> Result<u64> {
    ensure_canonical_unsigned_text(text)?;
    text.parse()
        .map_err(|_| TerminalError::InvalidMessage(format!("invalid u64 '{text}'")))
}

fn ensure_canonical_unsigned_text(text: &str) -> Result<()> {
    if text.is_empty() || (text.len() > 1 && text.starts_with('0')) {
        return Err(TerminalError::InvalidMessage(format!(
            "non-canonical integer '{text}'"
        )));
    }
    if text.starts_with('+') || text.starts_with('-') {
        return Err(TerminalError::InvalidMessage(format!(
            "non-canonical integer '{text}'"
        )));
    }
    Ok(())
}

fn parse_two_positive_i64(rest: &str) -> Result<(i64, i64)> {
    let (a, b) = split_once(rest, ':')?;
    if b.contains(':') {
        return Err(TerminalError::InvalidMessage(
            "unexpected extra ':' in framed ids".into(),
        ));
    }
    Ok((parse_positive_i64(a)?, parse_positive_i64(b)?))
}

fn invalid_message(reason: &str, wire: &str) -> TerminalError {
    let mut end = ERROR_WIRE_PREVIEW_CHARS.min(wire.len());
    while end > 0 && !wire.is_char_boundary(end) {
        end -= 1;
    }
    let preview = if wire.len() > end {
        format!("{}…", &wire[..end])
    } else {
        wire.to_string()
    };
    TerminalError::InvalidMessage(format!("{reason}: {preview}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(message: TerminalMessage) {
        let wire = encode_message(&message).expect("encode");
        let decoded = decode_message(&wire).expect("decode");
        assert_eq!(decoded, message, "wire={wire}");
    }

    #[test]
    fn output_roundtrip() {
        roundtrip(TerminalMessage::Output {
            stream_id: 1,
            frame_id: 2,
            data: Bytes::from_static(b"hello\n"),
        });
    }

    #[test]
    fn replay_roundtrip() {
        roundtrip(TerminalMessage::Replay {
            stream_id: 9,
            frame_id: 3,
            data: Bytes::from_static(&[0xff, 0x00, 0x01]),
        });
    }

    #[test]
    fn ack_input_resize_roundtrip() {
        roundtrip(TerminalMessage::OutputAck {
            stream_id: 4,
            frame_id: 11,
        });
        roundtrip(TerminalMessage::Input {
            stream_id: 4,
            origin: InputOrigin::User,
            data: Bytes::from_static(b"ls\r"),
        });
        roundtrip(TerminalMessage::Input {
            stream_id: 4,
            origin: InputOrigin::Parser,
            data: Bytes::from_static(b"\x1b[I"),
        });
        roundtrip(TerminalMessage::Resize {
            stream_id: 4,
            columns: 120,
            rows: 40,
        });
    }

    #[test]
    fn clipboard_hooks_roundtrip() {
        roundtrip(TerminalMessage::Clipboard(ClipboardHook::PasteRequest {
            request_id: 7,
            force: true,
        }));
        roundtrip(TerminalMessage::Clipboard(ClipboardHook::SelectionCopy {
            data: Bytes::from_static(b"selected"),
        }));
        roundtrip(TerminalMessage::Clipboard(ClipboardHook::PasteDrain {
            request_id: 7,
        }));
        roundtrip(TerminalMessage::Clipboard(ClipboardHook::PasteBegin {
            request_id: 7,
            force: false,
            total_utf8_bytes: 12,
        }));
        roundtrip(TerminalMessage::Clipboard(ClipboardHook::PasteChunk {
            request_id: 7,
            data: Bytes::from_static(b"paste-body"),
        }));
        roundtrip(TerminalMessage::Clipboard(ClipboardHook::PasteEnd {
            request_id: 7,
        }));
        roundtrip(TerminalMessage::Clipboard(ClipboardHook::PasteCancel {
            request_id: 7,
        }));
        assert_eq!(
            encode_message(&TerminalMessage::Clipboard(ClipboardHook::PasteChunk {
                request_id: 1,
                data: Bytes::from_static(b"x"),
            }))
            .unwrap(),
            "paste-chunk:1:eA=="
        );
    }

    #[test]
    fn host_control_frames_roundtrip() {
        roundtrip(TerminalMessage::FocusBarrier { stream_id: 3 });
        roundtrip(TerminalMessage::ParserBarrier { stream_id: 3 });
        roundtrip(TerminalMessage::Retirement { stream_id: 3 });
        roundtrip(TerminalMessage::Clear { stream_id: None });
        roundtrip(TerminalMessage::Clear {
            stream_id: Some(3),
        });
        roundtrip(TerminalMessage::Ready {
            columns: 80,
            rows: 24,
        });
        roundtrip(TerminalMessage::PageError {
            detail: "xterm.js bundle missing".into(),
        });
        roundtrip(TerminalMessage::CollapsedFit {
            detail: "19x7:100x50".into(),
        });
    }

    #[test]
    fn control_frames_roundtrip() {
        roundtrip(TerminalMessage::ParserBarrierReady { stream_id: 42 });
        roundtrip(TerminalMessage::FocusReady { stream_id: 42 });
        roundtrip(TerminalMessage::OutputWriteFailure {
            stream_id: 42,
            frame_id: 1,
        });
        roundtrip(TerminalMessage::ParserBarrierFailure { stream_id: 42 });
        roundtrip(TerminalMessage::TerminalClearFailure { stream_id: 42 });
        roundtrip(TerminalMessage::PageFatal {
            detail: "protocol".into(),
        });
        assert!(is_page_fatal_frame("fatal:protocol"));
        assert!(!is_page_fatal_frame("barrier:1"));
    }

    #[test]
    fn rejects_empty_output_payload() {
        let err = encode_message(&TerminalMessage::Output {
            stream_id: 1,
            frame_id: 1,
            data: Bytes::new(),
        })
        .unwrap_err();
        assert_eq!(err, TerminalError::EmptyPayload);
    }

    #[test]
    fn rejects_non_canonical_stream_id() {
        let err = decode_message("r:01:80x24").unwrap_err();
        assert!(matches!(err, TerminalError::InvalidMessage(_)));
    }

    #[test]
    fn rejects_signed_integers() {
        assert!(decode_message("a:+1:2").is_err());
        assert!(decode_message("a:-1:2").is_err());
        assert!(decode_message("r:1:+80x24").is_err());
    }

    #[test]
    fn rejects_oversized_output_frame() {
        let data = Bytes::from(vec![0u8; MAX_OUTPUT_FRAME_BYTES + 1]);
        let err = encode_message(&TerminalMessage::Output {
            stream_id: 1,
            frame_id: 1,
            data,
        })
        .unwrap_err();
        assert!(matches!(
            err,
            TerminalError::MessageTooLarge {
                kind: "output",
                ..
            }
        ));
    }

    #[test]
    fn rejects_oversized_wire_string() {
        let wire = "x".repeat(MAX_WIRE_CHARS + 1);
        let err = decode_message(&wire).unwrap_err();
        assert!(matches!(
            err,
            TerminalError::MessageTooLarge { kind: "wire", .. }
        ));
    }

    #[test]
    fn rejects_oversized_paste_begin() {
        let err = decode_message(&format!(
            "paste-begin:1:0:{}",
            MAX_CLIPBOARD_PASTE_UTF8_BYTES + 1
        ))
        .unwrap_err();
        assert!(matches!(
            err,
            TerminalError::MessageTooLarge { kind: "paste", .. }
        ));
    }

    #[test]
    fn rejects_non_canonical_paste_byte_count() {
        assert!(decode_message("paste-begin:1:0:01").is_err());
    }

    #[test]
    fn rejects_malformed_base64_and_unknown_frames() {
        assert!(decode_message("d:1:1:!!!!").is_err());
        assert!(decode_message("nope").is_err());
        assert!(decode_message("a:1:2:extra").is_err());
    }

    #[test]
    fn binary_safe_roundtrip_matches_csharp_nanowrite_fixture() {
        // C# TerminalBridgeMessagesTests: "Dw0=" → 0x0f, 0x0d
        let decoded = decode_message("d:1:1:Dw0=").unwrap();
        match decoded {
            TerminalMessage::Output { data, .. } => {
                assert_eq!(&data[..], &[0x0f, 0x0d]);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn csharp_encode_output_frame_golden_vectors() {
        // TerminalBridgeMessagesTests.EncodeOutputFrame_PreservesArbitraryTerminalBytes
        let frame = encode_message(&TerminalMessage::Output {
            stream_id: 7,
            frame_id: 9,
            data: Bytes::from_static(&[0x1b, 0x00, 0xff, 0xf0, 0x9f, 0x98, 0x80]),
        })
        .unwrap();
        assert_eq!(frame, "d:7:9:GwD/8J+YgA==");

        // EncodeReplayFrame_UsesSideEffectFreeReplayChannel
        let replay = encode_message(&TerminalMessage::Replay {
            stream_id: 7,
            frame_id: 9,
            data: Bytes::from_static(&[0x1b, 0x00, 0xff]),
        })
        .unwrap();
        assert_eq!(replay, "q:7:9:GwD/");

        // DecodeBase64Bytes_PreservesCtrlLClearScreen
        let ctrl_l = decode_message("d:1:1:DA==").unwrap();
        match ctrl_l {
            TerminalMessage::Output { data, .. } => assert_eq!(&data[..], &[0x0c]),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn csharp_input_frame_golden_vectors() {
        // TryParseInputFrame_AcceptsCanonicalStreamOriginAndReturnsPayloadOffset
        let user = decode_message("b:128:u:Gw==").unwrap();
        match user {
            TerminalMessage::Input {
                stream_id,
                origin,
                data,
            } => {
                assert_eq!(stream_id, 128);
                assert_eq!(origin, InputOrigin::User);
                assert_eq!(&data[..], &[0x1b]);
            }
            other => panic!("unexpected {other:?}"),
        }
        let parser = decode_message("b:128:p:Gw==").unwrap();
        match parser {
            TerminalMessage::Input { origin, .. } => assert_eq!(origin, InputOrigin::Parser),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn classify_sessionless_replay_matches_csharp_cases() {
        use SessionlessReplayDisposition::*;
        let cases = [
            ("barrier:42", Ready),
            ("barrier:41", Ignore),
            ("focus:42", Ignore),
            ("fatal:write:42:1", CurrentFailure),
            ("fatal:barrier:42", CurrentFailure),
            ("fatal:clear:42", CurrentFailure),
            ("fatal:write:41:1", RecoverableFatal),
            ("fatal:barrier:41", RecoverableFatal),
            ("fatal:clear:41", RecoverableFatal),
            ("fatal:protocol", RecoverableFatal),
            ("fatal:clear", RecoverableFatal),
            ("fatal:unknown-page-failure", RecoverableFatal),
            ("fatal:write:42:0", RecoverableFatal),
            ("fatal:write:42:1:extra", RecoverableFatal),
            ("ready:42", Ignore),
            ("barrier:01", Ignore),
            ("barrier:", Ignore),
        ];
        for (wire, expected) in cases {
            assert_eq!(
                classify_sessionless_replay_message(wire, 42).unwrap(),
                expected,
                "wire={wire}"
            );
        }
        assert!(classify_sessionless_replay_message("barrier:1", 0).is_err());
        assert!(classify_sessionless_replay_message("barrier:1", -1).is_err());
    }

    #[test]
    fn csharp_rejects_malformed_input_and_ack_frames() {
        for wire in [
            "b:",
            "b:1",
            "b:1:Gw==",
            "b:0:u:Gw==",
            "b:+1:u:Gw==",
            "b:01:u:Gw==",
            "b:1:",
            "b:1:u:",
            "b:1:x:Gw==",
            "b:1:U:Gw==",
            "b:1:user:Gw==",
            "b:1:u:Gw==:late",
            "a:1:u:Gw==",
            "a:",
            "a:1",
            "a:0:1",
            "a:1:0",
            "a:-1:2",
            "a:1:2:3",
            "a:+1:2",
            "a:01:2",
            "a:1:02",
            "p:0:0",
            "p:01:0",
            "p:1:2",
            "p:1:0:extra",
        ] {
            assert!(
                decode_message(wire).is_err(),
                "expected reject for {wire}"
            );
        }
    }

    #[test]
    fn try_parse_scoped_geometry_matches_csharp_usable_mins() {
        assert_eq!(
            try_parse_scoped_geometry("r:42:132x43", MIN_USABLE_COLUMNS, MIN_USABLE_ROWS),
            Some((42, 132, 43))
        );
        for wire in [
            "r:42:19x43",
            "r:42:132x7",
            "r:42:132",
            "r:0:132x43",
            "r:01:132x43",
            "r:42:0132x43",
            "r:42:132x43:1",
            "ready:42:132x43",
        ] {
            assert_eq!(
                try_parse_scoped_geometry(wire, MIN_USABLE_COLUMNS, MIN_USABLE_ROWS),
                None,
                "wire={wire}"
            );
        }
        // Raw decode still accepts positive geometry below usable mins.
        assert!(matches!(
            decode_message("r:42:19x43").unwrap(),
            TerminalMessage::Resize {
                columns: 19,
                rows: 43,
                ..
            }
        ));
    }

    #[test]
    fn error_preview_truncates_hostile_wire() {
        let wire = format!("zzz:{}", "A".repeat(400));
        let err = decode_message(&wire).unwrap_err();
        let msg = err.to_string();
        assert!(msg.len() < 400, "error embedded full wire: {msg}");
        assert!(msg.contains('…'));
    }

    #[test]
    fn error_preview_does_not_panic_on_multibyte_boundary() {
        // Build a wire whose raw bytes exceed the preview cap with a split char.
        let mut hostile = String::new();
        while hostile.len() < ERROR_WIRE_PREVIEW_CHARS - 1 {
            hostile.push('b');
        }
        hostile.push('€'); // 3-byte UTF-8 starting at byte 127
        hostile.push_str("tail");
        let err = decode_message(&hostile).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains('…'));
        assert!(!msg.contains("tail"));
    }
}
