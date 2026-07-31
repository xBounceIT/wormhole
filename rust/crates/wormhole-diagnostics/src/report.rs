//! Diagnostics report types and collection (no secrets).

use std::path::{Path, PathBuf};

use crate::sidecars::{
    collect_sidecar_matrix, touches_wormhole_secrets_dir, SidecarPresence, SidecarStatus,
};
use crate::webview2::{probe_webview2_runtime, WebView2RuntimeStatus};

/// Rust migration app/crate version reported in diagnostics (`CARGO_PKG_VERSION`).
pub const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Secrets-free support snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiagnosticsReport {
    /// `wormhole-diagnostics` / migration crate version.
    pub app_version: String,
    /// `rustc -V` stdout (trimmed), when the toolchain is on `PATH`.
    pub rustc_version: Option<String>,
    /// `std::env::consts::ARCH` (e.g. `x86_64`, `aarch64`).
    pub arch: String,
    /// `std::env::consts::OS`.
    pub os: String,
    /// Best-effort WebView2 Evergreen Runtime probe.
    pub webview2: WebView2RuntimeStatus,
    /// Presence matrix for known tunnel sidecar binaries.
    pub sidecars: Vec<SidecarPresence>,
    /// `%LOCALAPPDATA%\Wormhole\logs` (path only — contents never read).
    pub logs_dir: PathBuf,
}

/// Build a fresh report from the current process environment.
///
/// Never reads Credential Manager, DPAPI blobs, SQLite rows, or log file bodies.
pub fn collect_report() -> DiagnosticsReport {
    DiagnosticsReport {
        app_version: APP_VERSION.to_string(),
        rustc_version: probe_rustc_version(),
        arch: std::env::consts::ARCH.to_string(),
        os: std::env::consts::OS.to_string(),
        webview2: probe_webview2_runtime(),
        sidecars: collect_sidecar_matrix(),
        logs_dir: logs_dir(),
    }
}

/// Render a plain-text report suitable for terminals / bug pastes.
///
/// Defense in depth: never emits `Wormhole\keys` / `Wormhole\tunnels` paths or
/// `password=` / `token=` / `secret=` assignments even if a caller forged the struct.
pub fn format_report(report: &DiagnosticsReport) -> String {
    let mut out = String::new();
    out.push_str("=== Wormhole diagnostics (no secrets) ===\n");
    out.push_str(&format!("app_version: {}\n", report.app_version));
    match &report.rustc_version {
        Some(v) => out.push_str(&format!("rustc: {v}\n")),
        None => out.push_str("rustc: (not found on PATH)\n"),
    }
    out.push_str(&format!("platform: {}-{}\n", report.arch, report.os));
    out.push_str(&format!("logs_dir: {}\n", sanitize_logs_dir_display(&report.logs_dir)));
    out.push_str(&format!("webview2: {}\n", format_webview2(&report.webview2)));
    out.push_str("sidecars:\n");
    for row in &report.sidecars {
        out.push_str(&format_sidecar_row(row));
    }
    out.push_str("=== end diagnostics ===\n");
    // Defense in depth: scrub forged/odd field values that look like secret assignments.
    redact_secret_assignments(&out)
}

fn format_sidecar_row(row: &SidecarPresence) -> String {
    match &row.status {
        SidecarStatus::Present { path } if touches_wormhole_secrets_dir(path) => {
            // Should be unreachable after collect filtering; still never print the path.
            format!("  - {}: missing (secrets-path filtered)\n", row.name)
        }
        SidecarStatus::Present { path } => {
            format!("  - {}: present ({})\n", row.name, path.display())
        }
        SidecarStatus::Missing { searched } => {
            let n = searched
                .iter()
                .filter(|p| !touches_wormhole_secrets_dir(p))
                .count();
            format!("  - {}: missing (searched {n} candidate(s))\n", row.name)
        }
    }
}

fn sanitize_logs_dir_display(path: &Path) -> String {
    if touches_wormhole_secrets_dir(path) {
        "(redacted)".to_string()
    } else {
        path.display().to_string()
    }
}

fn format_webview2(status: &WebView2RuntimeStatus) -> String {
    match status {
        WebView2RuntimeStatus::Present { version, source } => {
            format!("present version={version} source={source}")
        }
        WebView2RuntimeStatus::NotFound => "not found (registry probe)".to_string(),
        WebView2RuntimeStatus::ProbeFailed { reason } => {
            format!("probe failed ({reason})")
        }
    }
}

/// Case-insensitive `password=` / `token=` / `secret=` value scrub (non-empty `\S+`).
fn redact_secret_assignments(input: &str) -> String {
    let mut out = input.to_string();
    for key in ["password", "token", "secret"] {
        out = redact_assignment_key(&out, key);
    }
    out
}

fn redact_assignment_key(input: &str, key: &str) -> String {
    let lower = input.to_ascii_lowercase();
    let key_lower = key.to_ascii_lowercase();
    let mut result = String::with_capacity(input.len());
    let mut i = 0;
    let bytes = input.as_bytes();
    let lower_bytes = lower.as_bytes();
    while i < bytes.len() {
        if let Some(rel) = lower[i..].find(&key_lower) {
            let start = i + rel;
            result.push_str(&input[i..start]);
            let after_key = start + key_lower.len();
            // optional spaces, then '='
            let mut j = after_key;
            while j < bytes.len() && lower_bytes[j] == b' ' {
                j += 1;
            }
            if j < bytes.len() && bytes[j] == b'=' {
                j += 1;
                while j < bytes.len() && lower_bytes[j] == b' ' {
                    j += 1;
                }
                let value_start = j;
                while j < bytes.len() && !bytes[j].is_ascii_whitespace() {
                    j += 1;
                }
                if value_start < j {
                    result.push_str(&input[start..value_start]);
                    result.push_str("[redacted]");
                    i = j;
                    continue;
                }
            }
            result.push_str(&input[start..after_key]);
            i = after_key;
        } else {
            result.push_str(&input[i..]);
            break;
        }
    }
    result
}

/// `%LOCALAPPDATA%\Wormhole\logs` — mirrors `wormhole_app::logs_dir` / AGENTS.md.
pub fn logs_dir() -> PathBuf {
    local_app_data().join("Wormhole").join("logs")
}

fn local_app_data() -> PathBuf {
    std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("USERPROFILE").map(|p| PathBuf::from(p).join("AppData").join("Local"))
        })
        .unwrap_or_else(|| PathBuf::from(r"C:\Users\Default\AppData\Local"))
}

fn probe_rustc_version() -> Option<String> {
    let output = std::process::Command::new("rustc").arg("-V").output().ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if text.is_empty() {
        None
    } else {
        Some(text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sidecars::SidecarStatus;
    use crate::webview2::WebView2RuntimeStatus;
    use std::path::PathBuf;

    fn assert_no_secret_leaks(text: &str) {
        let lower = text.to_ascii_lowercase();
        for key in ["password", "token", "secret"] {
            assert_assignments_redacted_or_absent(&lower, key, text);
        }
        // Credential blob dirs must never appear (path or body).
        assert!(
            !lower.contains(r"\wormhole\keys") && !lower.contains("/wormhole/keys"),
            "leaked Wormhole\\keys path in:\n{text}"
        );
        assert!(
            !lower.contains(r"\wormhole\tunnels") && !lower.contains("/wormhole/tunnels"),
            "leaked Wormhole\\tunnels path in:\n{text}"
        );
    }

    fn assert_assignments_redacted_or_absent(lower: &str, key: &str, original: &str) {
        let mut rest = lower;
        while let Some(idx) = rest.find(key) {
            let after_key = &rest[idx + key.len()..];
            let trimmed = after_key.trim_start_matches(' ');
            if let Some(stripped) = trimmed.strip_prefix('=') {
                let value = stripped.trim_start_matches(' ');
                assert!(
                    value.starts_with("[redacted]"),
                    "leaked {key}= assignment in:\n{original}"
                );
            }
            rest = &rest[idx + key.len()..];
        }
    }

    #[test]
    fn collect_and_format_contains_required_fields() {
        let report = collect_report();
        assert_eq!(report.app_version, APP_VERSION);
        assert!(!report.arch.is_empty());
        assert_eq!(report.os, "windows");
        assert_eq!(report.sidecars.len(), 4);
        assert_eq!(
            report.logs_dir.file_name().and_then(|s| s.to_str()),
            Some("logs")
        );

        let text = format_report(&report);
        assert!(text.contains("app_version:"));
        assert!(text.contains("platform:"));
        assert!(text.contains("logs_dir:"));
        assert!(text.contains("webview2:"));
        assert!(text.contains("sidecars:"));
        assert!(text.contains("wormhole-wgproxy.exe"));
        assert!(text.contains("wormhole-ovpnproxy.exe"));
        assert!(text.contains("wormhole-fortiproxy.exe"));
        assert!(text.contains("wormhole-ciscoproxy.exe"));

        assert_no_secret_leaks(&text);
    }

    #[test]
    fn logs_dir_is_under_wormhole() {
        let dir = logs_dir();
        let rendered = dir.to_string_lossy().to_ascii_lowercase();
        assert!(rendered.contains("wormhole"));
        assert!(
            rendered.ends_with("logs")
                || rendered.ends_with("logs\\")
                || rendered.ends_with("logs/")
        );
        assert!(!touches_wormhole_secrets_dir(&dir));
    }

    #[test]
    fn format_redacts_forged_secrets_sidecar_path() {
        let report = DiagnosticsReport {
            app_version: "0.0.0-test".into(),
            rustc_version: None,
            arch: "x86_64".into(),
            os: "windows".into(),
            webview2: WebView2RuntimeStatus::NotFound,
            sidecars: vec![SidecarPresence {
                name: "wormhole-wgproxy.exe",
                status: SidecarStatus::Present {
                    path: PathBuf::from(
                        r"C:\Users\x\AppData\Local\Wormhole\keys\wormhole-wgproxy.exe",
                    ),
                },
            }],
            logs_dir: PathBuf::from(r"C:\Users\x\AppData\Local\Wormhole\logs"),
        };
        let text = format_report(&report);
        assert!(text.contains("secrets-path filtered") || text.contains("missing"));
        assert_no_secret_leaks(&text);
    }

    #[test]
    fn format_redacts_forged_secrets_logs_dir() {
        let report = DiagnosticsReport {
            app_version: "0.0.0-test".into(),
            rustc_version: Some("rustc 1.0.0".into()),
            arch: "x86_64".into(),
            os: "windows".into(),
            webview2: WebView2RuntimeStatus::ProbeFailed {
                reason: "access denied".into(),
            },
            sidecars: vec![],
            logs_dir: PathBuf::from(r"C:\Users\x\AppData\Local\Wormhole\tunnels"),
        };
        let text = format_report(&report);
        assert!(text.contains("logs_dir: (redacted)"));
        assert!(text.contains("probe failed (access denied)"));
        assert_no_secret_leaks(&text);
    }

    #[test]
    fn format_missing_counts_ignore_secret_candidates() {
        let report = DiagnosticsReport {
            app_version: "0.0.0-test".into(),
            rustc_version: None,
            arch: "x86_64".into(),
            os: "windows".into(),
            webview2: WebView2RuntimeStatus::NotFound,
            sidecars: vec![SidecarPresence {
                name: "wormhole-ovpnproxy.exe",
                status: SidecarStatus::Missing {
                    searched: vec![
                        PathBuf::from(r"C:\app\bin\wormhole-ovpnproxy.exe"),
                        PathBuf::from(
                            r"C:\Users\x\AppData\Local\Wormhole\tunnels\wormhole-ovpnproxy.exe",
                        ),
                    ],
                },
            }],
            logs_dir: PathBuf::from(r"C:\Users\x\AppData\Local\Wormhole\logs"),
        };
        let text = format_report(&report);
        assert!(text.contains("missing (searched 1 candidate(s))"));
        assert_no_secret_leaks(&text);
    }

    #[test]
    fn format_scrubs_forged_assignment_secrets() {
        let report = DiagnosticsReport {
            app_version: "password=s3cret".into(),
            rustc_version: Some("token = abc".into()),
            arch: "x86_64".into(),
            os: "windows".into(),
            webview2: WebView2RuntimeStatus::ProbeFailed {
                reason: "secret=blob".into(),
            },
            sidecars: vec![],
            logs_dir: PathBuf::from(r"C:\Users\x\AppData\Local\Wormhole\logs"),
        };
        let text = format_report(&report);
        assert!(text.contains("password=[redacted]"));
        assert!(text.contains("token = [redacted]") || text.contains("token=[redacted]"));
        assert!(text.contains("secret=[redacted]"));
        assert_no_secret_leaks(&text);
    }
}
