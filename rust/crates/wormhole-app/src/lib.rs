//! Wormhole Rust app composition root.
//!
//! Wires `Arc<dyn Trait>` placeholders for domain / storage / secrets / tunnels / MCP /
//! UI / VNC / HTTP / SFTP / update / session. Sibling crates are optional features so the
//! workspace still builds when they are absent. With `secrets`, also exposes Hello unlock
//! prompt UI glue (`hello_unlock` — Fake Success/Cancel/Unavailable; no GPUI / WinRT).

mod logging;
mod logging_boot;
mod placeholders;
mod services;

#[cfg(feature = "secrets")]
mod hello_unlock;

#[cfg(all(feature = "ui", feature = "session"))]
mod session_tabs;

pub use logging::{
    current_day_log_file_path, init_tracing, init_tracing_with_dirs, log_file_path_for_date,
    logs_dir, redact_log_text, TracingGuard, DEFAULT_LOG_RETENTION_DAYS,
};
pub use logging_boot::{
    apply_logging_boot, enrich_log_line, normalize_retention_days, AppliedLogging, FakeLogSink,
    LoggingBootConfig, MAX_LOG_RETENTION_DAYS, MIN_LOG_RETENTION_DAYS,
};
pub use placeholders::{ConnectionStore, SecretStore, StubConnectionStore, StubSecretStore};
pub use services::{build_default_services, AppServices, AppServicesBuilder};

#[cfg(feature = "secrets")]
pub use hello_unlock::{
    fake_prompt_for_outcome, FakeHelloUnlockUi, HelloUnlockGlue, HelloUnlockOutcome,
    HelloUnlockResult, HelloUnlockSource, SharedHelloUnlockSource, DEFAULT_UNLOCK_PROMPT,
    HELLO_AVAILABLE_MESSAGE, HELLO_CANCELED_MESSAGE, HELLO_VERIFIED_MESSAGE, WAITING_FOR_HELLO,
};

#[cfg(all(feature = "ui", feature = "session"))]
pub use session_tabs::{
    close_tab_and_dispose, close_tab_and_dispose_session, close_tab_on_session_closed,
    from_ui_session_id, open_tab_for_session, to_ui_session_id, SessionBinding, SessionBindings,
    SessionTabGlueError,
};

#[cfg(feature = "vnc")]
pub use services::VncHandle;

#[cfg(feature = "sftp")]
pub use services::SftpHandle;

#[cfg(feature = "domain")]
pub use services::DomainMarker;

#[cfg(feature = "session")]
pub use services::SessionHandleMarker;
