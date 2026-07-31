//! PTY-like terminal session traits and xterm.js bridge message types.
//!
//! Mirrors the C# `ITerminalSession` surface and the WebView2 ↔ native wire
//! format in `Interop/Terminal/TerminalBridgeMessages.cs` / `Assets/web/bridge.js`.

mod backpressure;
mod clipboard;
mod error;
mod messages;
mod paste_glue;
mod session;
mod settings_apply;

pub use backpressure::{
    BackpressureAction, OutputBackpressure, HIGH_WATERMARK_BYTES, IMMEDIATE_FRAME_THRESHOLD_BYTES,
    LOW_WATERMARK_BYTES, MAX_PENDING_WEB_MESSAGES,
};
pub use clipboard::{
    build_paste_transaction, read_paste_text, ClipboardError, FakeClipboard, HostClipboard,
    CLIPBOARD_PASTE_CHUNK_CHARS,
};
pub use error::TerminalError;
pub use messages::{
    classify_sessionless_replay_message, decode_message, encode_message, is_page_fatal_frame,
    try_parse_scoped_geometry, ClipboardHook, InputOrigin, SessionlessReplayDisposition,
    TerminalMessage, MAX_CLIPBOARD_PASTE_UTF8_BYTES, MAX_INPUT_FRAME_UTF8_BYTES,
    MAX_OUTPUT_FRAME_BYTES, MAX_SELECTION_UTF8_BYTES, MAX_WIRE_CHARS, MIN_USABLE_COLUMNS,
    MIN_USABLE_ROWS,
};
pub use paste_glue::{
    paste_request_to_fake_session, paste_request_to_session, PasteSessionError, PasteToSessionResult,
};
pub use session::{
    channel_stub_pair, FakeTerminalSession, TerminalEvent, TerminalEventReceiver,
    TerminalEventSender, TerminalSession, TerminalSize, CHANNEL_STUB_CAPACITY,
};
pub use settings_apply::{
    accept_selection_auto_copy, apply_terminal_settings, terminal_settings_apply_messages,
    validate_terminal_settings, AppliedTerminalSettings, FakeTerminalSettingsSurface,
    TerminalSettingsApplyError, TerminalSettingsApplyMessage, TerminalSettingsConfig,
    DEFAULT_SSH_FONT_FAMILY, DEFAULT_SSH_FONT_SIZE,
};

#[cfg(all(windows, feature = "clipboard-win"))]
pub use clipboard::win32::Win32Clipboard;

/// Crate-level result alias.
pub type Result<T> = std::result::Result<T, TerminalError>;
