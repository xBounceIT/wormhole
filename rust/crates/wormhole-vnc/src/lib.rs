//! VNC / RFB subset for Wormhole (parity with C# `Community.MarcusW.VncClient` usage).
//!
//! v1 supports **no-auth** and **classic VNC password** only. Framebuffer + input
//! are traits so a GPUI/WinUI render surface can plug in later.
//!
//! Default builds ship:
//! - protocol / auth types
//! - [`auth_glue`] — no-auth vs VNC password select; username/domain ignored; Fake provider
//! - [`RawPixelBuffer`] with damage-rect merge (Raw encoding decode stub)
//! - bounded [`InputEventQueue`] for pointer/key enqueue
//! - [`session_glue`] — pointer/key → queue; Raw FB rect → dirty notify Fake
//! - [`clipboard_glue`] — ClientCutText → Fake send; ServerCutText → local buffer
//! - [`select_vnc_connect_target`] — Direct vs loopback forwarder (no SOCKS)
//!
//! Engine choice: prefer crates.io [`vnc-rs`](https://crates.io/crates/vnc-rs) behind
//! feature `engine` when wiring a live client — see `docs/migration/09-vnc.md`.
//! Live TCP is still deferred even with `engine` enabled.

mod auth;
mod auth_glue;
mod clipboard_glue;
mod error;
mod framebuffer;
mod input;
mod protocol;
mod session;
mod session_glue;
mod target;

#[cfg(feature = "engine")]
mod engine;

pub use auth::{
    password_is_usable, resolve_auth, VncAuthMethod, VncPassword, MAX_VNC_PASSWORD_BYTES,
    MAX_VNC_PASSWORD_CHARS,
};
pub use auth_glue::{
    provide_vnc_auth_input, resolve_vnc_auth_from_provider, select_vnc_auth, FakeVncPasswordProvider,
    VncAuthFields, VncAuthInputKind, VncAuthSelection, VncPasswordProvider,
};
pub use clipboard_glue::{
    apply_server_cut_text, local_clipboard_utf8_len, send_clipboard_to_session,
    validate_clipboard_utf8_len, CutTextPayload, MAX_VNC_CLIPBOARD_UTF8_BYTES,
};
pub use error::VncError;
pub use framebuffer::{
    DamageRect, DamageTracker, FramebufferPixelFormat, FramebufferRect, FramebufferSink,
    MemoryFramebuffer, PixelFormatKind, RawPixelBuffer,
};
pub use input::{
    InputEvent, InputEventQueue, KeyEvent, PointerButtons, PointerEvent, RecordingInput,
    VncInputSink, DEFAULT_INPUT_QUEUE_CAPACITY,
};
pub use protocol::{
    RfbSecurityType, RfbVersion, SECURITY_TYPE_NONE, SECURITY_TYPE_VNC_AUTH,
};
pub use session::{VncConnectOptions, VncSession, VncSessionState};
pub use session_glue::{
    apply_framebuffer_rect, push_key_to_session, push_pointer_to_session, FakeFramebufferDirtyNotify,
    FramebufferDirtyNotify, NoopFramebufferDirtyNotify, VncSessionGlue,
};
pub use target::{
    forwarder_socket_addr, select_vnc_connect_target, FakeForwarderBind, FakeTunnelForwarder,
    TunnelLocalForwarderSource, VncConnectTarget,
};

#[cfg(feature = "engine")]
pub use engine::VncRsEngineMarker;

/// Crate-level result alias.
pub type Result<T> = std::result::Result<T, VncError>;
