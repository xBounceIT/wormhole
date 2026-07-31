//! Wormhole support diagnostics + soak/benchmark harness stubs.
//!
//! Collects a **secrets-free** environment report (versions, arch, WebView2
//! runtime presence, sidecar binary matrix, log directory) for paste into bug
//! reports. Also hosts soak harness stubs + thin [`SoakRunner`] glue (FakeClock
//! unit path) — see `docs/migration/19-diagnostics-soak.md`.
//!
//! ```text
//! cargo run -p surface-lab -- --diagnostics
//! cargo test -p wormhole-diagnostics
//! ```

mod report;
mod runner;
mod sidecars;
mod soak;
mod webview2;

pub use report::{collect_report, format_report, DiagnosticsReport, APP_VERSION};
pub use runner::{
    FakeClock, MonoInstant, SoakClock, SoakError, SoakPhase, SoakReport, SoakRunner, SoakStatus,
    SystemClock,
};
pub use sidecars::{SidecarPresence, SidecarStatus};
pub use soak::{quad_pane_layout_stress, MAX_PANES, SOAK_SESSION_HOURS};
pub use webview2::{probe_webview2_runtime, WebView2RuntimeStatus};
