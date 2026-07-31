//! Best-effort WebView2 Evergreen Runtime presence (registry only — no COM bootstrap).

use windows::core::HSTRING;
use windows::Win32::Foundation::{
    ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND, ERROR_SUCCESS, WIN32_ERROR,
};
use windows::Win32::System::Registry::{
    RegCloseKey, RegGetValueW, RegOpenKeyExW, HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE,
    KEY_READ, RRF_RT_REG_SZ,
};

/// Evergreen WebView2 Runtime client GUID (Microsoft EdgeUpdate).
const WEBVIEW2_CLIENT_GUID: &str = "{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}";

/// Result of a registry probe for the WebView2 Runtime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WebView2RuntimeStatus {
    /// `pv` (product version) found under an EdgeUpdate Clients key.
    Present {
        version: String,
        /// Which hive/path yielded the hit (short label, not a full secret path).
        source: &'static str,
    },
    /// No known registry key / `pv` value.
    NotFound,
    /// Windows API call failed in an unexpected way (still secrets-free).
    ProbeFailed { reason: String },
}

/// Probe HKLM / HKCU EdgeUpdate Clients keys for the WebView2 Runtime `pv` value.
///
/// Does **not** call `CreateCoreWebView2Environment` — presence only.
/// Failures are soft: never panics; unexpected API errors become [`ProbeFailed`]
/// only when every hive fails that way (a miss on any hive → [`NotFound`]).
pub fn probe_webview2_runtime() -> WebView2RuntimeStatus {
    // Order: machine-wide WOW6432Node (typical x64), then native HKLM, then per-user.
    const CANDIDATES: &[(HKEY, &str, &str)] = &[
        (
            HKEY_LOCAL_MACHINE,
            r"SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients",
            "HKLM/WOW6432Node",
        ),
        (
            HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\EdgeUpdate\Clients",
            "HKLM",
        ),
        (
            HKEY_CURRENT_USER,
            r"SOFTWARE\Microsoft\EdgeUpdate\Clients",
            "HKCU",
        ),
    ];

    let mut last_err: Option<String> = None;
    let mut saw_miss = false;

    for &(root, base, label) in CANDIDATES {
        match read_pv(root, base) {
            Ok(Some(version)) => {
                return WebView2RuntimeStatus::Present {
                    version,
                    source: label,
                };
            }
            Ok(None) => {
                saw_miss = true;
            }
            Err(reason) => {
                last_err = Some(reason);
            }
        }
    }

    if saw_miss {
        WebView2RuntimeStatus::NotFound
    } else if let Some(reason) = last_err {
        WebView2RuntimeStatus::ProbeFailed { reason }
    } else {
        WebView2RuntimeStatus::NotFound
    }
}

fn is_missing_key_status(status: WIN32_ERROR) -> bool {
    status == ERROR_FILE_NOT_FOUND || status == ERROR_PATH_NOT_FOUND
}

fn read_pv(root: HKEY, base: &str) -> Result<Option<String>, String> {
    let sub = format!("{base}\\{WEBVIEW2_CLIENT_GUID}");
    let sub_h = HSTRING::from(sub.as_str());
    unsafe {
        let mut key = Default::default();
        let opened = RegOpenKeyExW(root, &sub_h, Some(0), KEY_READ, &mut key);
        if opened != ERROR_SUCCESS {
            return if is_missing_key_status(opened) {
                Ok(None)
            } else {
                Err(format!("RegOpenKeyExW: {opened:?}"))
            };
        }

        let name = HSTRING::from("pv");
        let mut data = vec![0u16; 256];
        let mut data_size = (data.len() * 2) as u32;
        let mut data_type = Default::default();

        let status = RegGetValueW(
            key,
            None,
            &name,
            RRF_RT_REG_SZ,
            Some(&mut data_type),
            Some(data.as_mut_ptr().cast()),
            Some(&mut data_size),
        );
        let _ = RegCloseKey(key);

        // Missing / oversized / wrong-type `pv` → soft miss (NotFound), never panic.
        if status != ERROR_SUCCESS {
            return Ok(None);
        }

        let u16_len = (data_size as usize / 2).saturating_sub(1); // drop NUL
        let end = u16_len.min(data.len());
        let version = String::from_utf16_lossy(&data[..end])
            .trim_end_matches('\0')
            .trim()
            .to_string();
        if version.is_empty() {
            Ok(None)
        } else {
            Ok(Some(version))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_returns_a_defined_status() {
        // CI agents may or may not have WebView2; any enum variant is acceptable.
        let status = probe_webview2_runtime();
        match status {
            WebView2RuntimeStatus::Present { version, source } => {
                assert!(!version.is_empty(), "empty pv");
                assert!(!source.is_empty());
                assert!(!version.to_ascii_lowercase().contains("password"));
            }
            WebView2RuntimeStatus::NotFound => {}
            WebView2RuntimeStatus::ProbeFailed { reason } => {
                assert!(!reason.is_empty());
                assert!(!reason.to_ascii_lowercase().contains("password="));
            }
        }
    }

    #[test]
    fn probe_never_panics() {
        let result = std::panic::catch_unwind(probe_webview2_runtime);
        assert!(result.is_ok(), "registry probe must be soft (no panic)");
    }

    #[test]
    fn missing_key_statuses_are_recognized() {
        assert!(is_missing_key_status(ERROR_FILE_NOT_FOUND));
        assert!(is_missing_key_status(ERROR_PATH_NOT_FOUND));
        assert!(!is_missing_key_status(ERROR_SUCCESS));
    }
}
