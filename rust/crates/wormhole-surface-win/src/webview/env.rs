//! Unique WebView2 user-data folders (environment isolation).
//!
//! WebView2 forbids sharing a user-data folder across controllers with mismatched
//! environment options (proxy args, ignore-cert AlwaysAllow, extensions). Wormhole
//! therefore allocates a **unique** temp folder per [`crate::webview::ChildWebViewHost`].
//! Shared hardening-only envs (C# shared CoreWebView2Environment) remain a later
//! optimization — unique folders never leak cert/proxy policy across tabs.
//!
//! Policy mapping: [`crate::webview::cert_policy_to_webview2_behavior`]
//! (`Default` → validate; `IgnoreErrors` → AlwaysAllow only) plus leaf/target glue
//! [`crate::webview::http_ignore_cert_to_webview2_behavior`] /
//! [`crate::webview::target_cert_to_webview2_behavior`] (fail-closed unless
//! HTTPS ∧ leaf `HttpIgnoreCertErrors`). Lab/create does **not** subscribe AlwaysAllow
//! and must not pass `--ignore-certificate-errors` as a silent substitute
//! (see host create-path hook comment).

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static UDF_SEQ: AtomicU64 = AtomicU64::new(0);

/// Allocate a unique empty user-data directory under the process temp folder.
pub fn unique_user_data_dir() -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let seq = UDF_SEQ.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "wormhole-webview-{}-{}-{}",
        std::process::id(),
        nanos,
        seq
    ));
    let _ = fs::create_dir_all(&dir);
    dir
}

/// Best-effort cleanup of a host user-data folder (locks may keep it until process exit).
pub fn try_remove_user_data_dir(path: &std::path::Path) {
    let _ = fs::remove_dir_all(path);
}

/// True when additional browser args require a dedicated environment / UDF
/// (must never share with hardening-only tabs).
pub fn args_require_isolated_udf(additional_browser_args: Option<&str>) -> bool {
    let Some(args) = additional_browser_args else {
        return false;
    };
    let lower = args.to_ascii_lowercase();
    lower.contains("--proxy-server=")
        || lower.contains("--proxy-bypass-list=")
        // Future ignore-cert switches / enterprise policy knobs that fingerprint the env.
        || lower.contains("ignore-certificate-errors")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unique_dirs_differ() {
        let a = unique_user_data_dir();
        let b = unique_user_data_dir();
        assert_ne!(a, b);
        assert!(a.exists());
        assert!(b.exists());
        try_remove_user_data_dir(&a);
        try_remove_user_data_dir(&b);
    }

    #[test]
    fn proxy_args_require_isolation() {
        assert!(!args_require_isolated_udf(None));
        assert!(!args_require_isolated_udf(Some("--disable-features=msWebOOUI")));
        assert!(args_require_isolated_udf(Some(
            "--proxy-server=socks5://127.0.0.1:9 --proxy-bypass-list=<-loopback>"
        )));
        assert!(args_require_isolated_udf(Some(
            "--ignore-certificate-errors"
        )));
    }
}
