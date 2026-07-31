//! Windows Hello availability + verification stubs.
//!
//! Mirrors `Services/Security/WindowsHelloService.cs` and
//! `RemoteDesktopSessionDetector.cs` for the remote-session gate. Interactive
//! consent UI (`Windows.Security.Credentials.UI.UserConsentVerifier`) is a
//! **WinRT** API and is **not** wired here yet — see [`WINRT_HELLO_GAP`].
//!
//! # Traits
//!
//! - [`AvailabilityProbe`] — can Hello be offered? (remote gate + WinRT gap)
//! - [`HelloPrompt`] — request interactive verification (fail-closed until WinRT)
//!
//! Unit tests inject [`FakeHelloPrompt`] (no WinRT, no biometric UI). Production
//! uses [`StubHelloPrompt`] / the free-function helpers, which never claim
//! `available` / `verified` until WinRT lands.
//!
//! **Never** log biometric material, PIN/password fallbacks, or caller prompt
//! strings that may embed secrets. Result messages are fixed UI copy only.

use std::fmt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

/// Message when Hello is blocked because the session is remote (parity with C#).
pub const REMOTE_DESKTOP_UNAVAILABLE_MESSAGE: &str = "Remote Desktop session detected. Windows Hello is disabled in remote sessions. Use your configured fallback method to unlock Wormhole.";

/// Documented gap: full Hello UI needs WinRT `UserConsentVerifier`.
///
/// The shipping C# app calls:
/// - `UserConsentVerifier.CheckAvailabilityAsync()`
/// - `UserConsentVerifier.RequestVerificationAsync(message)` or
///   `UserConsentVerifierInterop.RequestVerificationForWindowAsync(ownerHwnd, message)`
///
/// Those types live in the Windows Runtime (WinRT / UWP projection), not in the
/// Win32 `windows` crate surface used by this crate today. Bridging them from
/// Rust typically means `windows` WinRT features + an async runtime that can
/// pump the consent UI on an STA thread with an owner HWND from the GPUI host.
/// Until that lands, callers must unlock via PIN/password fallback against the
/// DPAPI app-auth store ([`crate::app_auth`]).
pub const WINRT_HELLO_GAP: &str = "Windows Hello interactive verification requires WinRT UserConsentVerifier (not yet wired in Rust). Use the configured PIN/password fallback to unlock Wormhole.";

/// `SM_REMOTESESSION` (`0x1000`) — `Helpers/Win32Interop.cs`.
pub const SM_REMOTESESSION: i32 = 0x1000;

/// Result of a Hello availability probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelloAvailability {
    /// Whether interactive Hello may be offered.
    pub available: bool,
    /// Human-readable reason (safe to show in UI; never contains secrets).
    pub message: String,
}

impl HelloAvailability {
    /// Convenience constructor.
    pub fn new(available: bool, message: impl Into<String>) -> Self {
        Self {
            available,
            message: message.into(),
        }
    }
}

/// Result of a Hello verification attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelloVerification {
    /// Whether the user was verified.
    pub verified: bool,
    /// Human-readable reason (safe to show in UI).
    pub message: String,
}

impl HelloVerification {
    /// Convenience constructor.
    pub fn new(verified: bool, message: impl Into<String>) -> Self {
        Self {
            verified,
            message: message.into(),
        }
    }
}

impl fmt::Display for HelloAvailability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} ({})",
            self.message,
            if self.available {
                "available"
            } else {
                "unavailable"
            }
        )
    }
}

impl fmt::Display for HelloVerification {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} ({})",
            self.message,
            if self.verified {
                "verified"
            } else {
                "rejected"
            }
        )
    }
}

/// Probe whether Windows Hello may be offered.
///
/// Implementations must not invoke biometric UI and must never log secrets.
pub trait AvailabilityProbe: Send + Sync {
    /// Result of the availability check (UI-safe message only).
    fn check_availability(&self) -> HelloAvailability;
}

/// Interactive Hello consent prompt (WinRT `UserConsentVerifier` when wired).
///
/// Until WinRT lands, production stubs fail closed. Implementations must **never**
/// write biometric material or the caller `message` (may embed secrets) to logs.
pub trait HelloPrompt: Send + Sync {
    /// Request verification. `owner_hwnd` / `message` mirror C# API parity.
    fn request_verification(&self, owner_hwnd: isize, message: &str) -> HelloVerification;
}

/// Production stub: remote-session gate + [`WINRT_HELLO_GAP`] (never claims ready).
///
/// Interactive WinRT `UserConsentVerifier` is **not** wired. Use PIN/password
/// fallback via [`crate::app_auth`].
#[derive(Debug, Default, Clone, Copy)]
pub struct StubHelloPrompt;

impl AvailabilityProbe for StubHelloPrompt {
    fn check_availability(&self) -> HelloAvailability {
        check_hello_availability()
    }
}

impl HelloPrompt for StubHelloPrompt {
    fn request_verification(&self, owner_hwnd: isize, message: &str) -> HelloVerification {
        request_hello_verification(owner_hwnd, message)
    }
}

/// Scripted Hello probe + prompt for unit tests (no WinRT, no biometric UI).
///
/// Configure availability / verification outcomes explicitly. Call counts are
/// tracked; the last prompt string is **not** retained. [`Debug`] exposes only
/// availability/verification booleans and call counts — never freeform messages
/// (avoids secret echo in harness logs / panic formatting).
pub struct FakeHelloPrompt {
    availability: Mutex<HelloAvailability>,
    verification: Mutex<HelloVerification>,
    availability_calls: AtomicUsize,
    verification_calls: AtomicUsize,
}

impl Default for FakeHelloPrompt {
    fn default() -> Self {
        Self::winrt_gap()
    }
}

impl fmt::Debug for FakeHelloPrompt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never dump freeform message strings (scripted UI copy or accidental secrets).
        // Caller prompts are not retained; Debug only exposes booleans + call counts.
        // Snapshot flags under separate locks (never hold both mutexes at once).
        let available = self.availability_guard().available;
        let verified = self.verification_guard().verified;
        f.debug_struct("FakeHelloPrompt")
            .field("availability_available", &available)
            .field("verification_verified", &verified)
            .field(
                "availability_calls",
                &self.availability_calls.load(Ordering::SeqCst),
            )
            .field(
                "verification_calls",
                &self.verification_calls.load(Ordering::SeqCst),
            )
            .finish()
    }
}

impl FakeHelloPrompt {
    fn availability_guard(&self) -> std::sync::MutexGuard<'_, HelloAvailability> {
        self.availability
            .lock()
            .unwrap_or_else(|p| p.into_inner())
    }

    fn verification_guard(&self) -> std::sync::MutexGuard<'_, HelloVerification> {
        self.verification
            .lock()
            .unwrap_or_else(|p| p.into_inner())
    }

    /// Fail-closed fake matching production stub messages (local / WinRT gap).
    pub fn winrt_gap() -> Self {
        Self::with_outcomes(
            HelloAvailability::new(false, WINRT_HELLO_GAP),
            HelloVerification::new(false, WINRT_HELLO_GAP),
        )
    }

    /// Remote-session unavailable (parity with C# RDP gate).
    pub fn remote_session() -> Self {
        Self::with_outcomes(
            HelloAvailability::new(false, REMOTE_DESKTOP_UNAVAILABLE_MESSAGE),
            HelloVerification::new(false, REMOTE_DESKTOP_UNAVAILABLE_MESSAGE),
        )
    }

    /// Explicit outcomes (tests only — do not put secrets in `message` fields).
    pub fn with_outcomes(availability: HelloAvailability, verification: HelloVerification) -> Self {
        Self {
            availability: Mutex::new(availability),
            verification: Mutex::new(verification),
            availability_calls: AtomicUsize::new(0),
            verification_calls: AtomicUsize::new(0),
        }
    }

    /// Configure the next availability result.
    pub fn set_availability(&self, availability: HelloAvailability) {
        *self.availability_guard() = availability;
    }

    /// Configure the next verification result.
    pub fn set_verification(&self, verification: HelloVerification) {
        *self.verification_guard() = verification;
    }

    /// How many times [`AvailabilityProbe::check_availability`] was called.
    pub fn availability_calls(&self) -> usize {
        self.availability_calls.load(Ordering::SeqCst)
    }

    /// How many times [`HelloPrompt::request_verification`] was called.
    pub fn verification_calls(&self) -> usize {
        self.verification_calls.load(Ordering::SeqCst)
    }
}

impl AvailabilityProbe for FakeHelloPrompt {
    fn check_availability(&self) -> HelloAvailability {
        self.availability_calls.fetch_add(1, Ordering::SeqCst);
        self.availability_guard().clone()
    }
}

impl HelloPrompt for FakeHelloPrompt {
    fn request_verification(&self, owner_hwnd: isize, message: &str) -> HelloVerification {
        let _ = (owner_hwnd, message); // never retain — may embed secrets
        self.verification_calls.fetch_add(1, Ordering::SeqCst);
        self.verification_guard().clone()
    }
}

/// Detect a remote desktop session (`SM_REMOTESESSION` or `SESSIONNAME` starting with `RDP-`).
///
/// Injectable hooks keep unit tests off the real metrics/env.
pub fn is_remote_desktop_session_with(
    get_system_metrics: impl Fn(i32) -> i32,
    get_env: impl Fn(&str) -> Option<String>,
) -> bool {
    if get_system_metrics(SM_REMOTESESSION) != 0 {
        return true;
    }
    get_env("SESSIONNAME")
        .map(|name| name.get(..4).is_some_and(|p| p.eq_ignore_ascii_case("RDP-")))
        .unwrap_or(false)
}

/// Production remote-session probe.
pub fn is_remote_desktop_session() -> bool {
    #[cfg(windows)]
    {
        is_remote_desktop_session_with(get_system_metrics_windows, |key| {
            std::env::var(key).ok()
        })
    }
    #[cfg(not(windows))]
    {
        is_remote_desktop_session_with(|_| 0, |key| std::env::var(key).ok())
    }
}

/// Check whether Windows Hello can be offered.
///
/// 1. Remote sessions → unavailable (parity with C#; never calls WinRT).
/// 2. Otherwise → unavailable with [`WINRT_HELLO_GAP`] until interactive WinRT
///    `UserConsentVerifier` is wired. Callers should use PIN/password fallback.
pub fn check_hello_availability() -> HelloAvailability {
    check_hello_availability_with(is_remote_desktop_session)
}

/// Availability check with an injectable remote-session probe (tests).
pub fn check_hello_availability_with(is_remote: impl FnOnce() -> bool) -> HelloAvailability {
    if is_remote() {
        return HelloAvailability::new(false, REMOTE_DESKTOP_UNAVAILABLE_MESSAGE);
    }
    HelloAvailability::new(false, WINRT_HELLO_GAP)
}

/// Stub interactive Hello verification.
///
/// Always fails closed: remote sessions get the RDP message; otherwise
/// [`WINRT_HELLO_GAP`]. `owner_hwnd` / `message` are accepted for API parity
/// with C# `RequestVerificationAsync` and ignored until WinRT lands.
pub fn request_hello_verification(owner_hwnd: isize, message: &str) -> HelloVerification {
    request_hello_verification_with(is_remote_desktop_session, owner_hwnd, message)
}

/// Verification stub with injectable remote-session probe (tests).
pub fn request_hello_verification_with(
    is_remote: impl FnOnce() -> bool,
    owner_hwnd: isize,
    message: &str,
) -> HelloVerification {
    let _ = (owner_hwnd, message);
    if is_remote() {
        return HelloVerification::new(false, REMOTE_DESKTOP_UNAVAILABLE_MESSAGE);
    }
    HelloVerification::new(false, WINRT_HELLO_GAP)
}

#[cfg(windows)]
fn get_system_metrics_windows(index: i32) -> i32 {
    use windows::Win32::UI::WindowsAndMessaging::{GetSystemMetrics, SYSTEM_METRICS_INDEX};
    unsafe { GetSystemMetrics(SYSTEM_METRICS_INDEX(index)) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_metric_marks_session_remote() {
        assert!(is_remote_desktop_session_with(|_| 1, |_| None));
        // Metric gate wins even when SESSIONNAME looks local (C# detector order).
        assert!(is_remote_desktop_session_with(|_| 1, |_| Some("Console".into())));
        assert_eq!(SM_REMOTESESSION, 0x1000);
    }

    #[test]
    fn sessionname_rdp_prefix_marks_remote() {
        assert!(is_remote_desktop_session_with(
            |_| 0,
            |k| {
                if k == "SESSIONNAME" {
                    Some("RDP-Tcp#1".into())
                } else {
                    None
                }
            }
        ));
        assert!(is_remote_desktop_session_with(
            |_| 0,
            |_| Some("rdp-tcp#9".into())
        ));
    }

    #[test]
    fn local_console_not_remote() {
        assert!(!is_remote_desktop_session_with(
            |_| 0,
            |_| Some("Console".into())
        ));
    }

    #[test]
    fn availability_remote_uses_fallback_message() {
        let a = check_hello_availability_with(|| true);
        assert!(!a.available);
        assert_eq!(a.message, REMOTE_DESKTOP_UNAVAILABLE_MESSAGE);
    }

    #[test]
    fn availability_local_documents_winrt_gap() {
        let a = check_hello_availability_with(|| false);
        assert!(!a.available);
        assert_eq!(a.message, WINRT_HELLO_GAP);
        assert!(a.message.contains("WinRT"));
        assert!(a.message.contains("UserConsentVerifier"));
    }

    #[test]
    fn verification_stub_never_succeeds() {
        let remote = request_hello_verification_with(|| true, 0, "Unlock Wormhole");
        assert!(!remote.verified);
        assert_eq!(remote.message, REMOTE_DESKTOP_UNAVAILABLE_MESSAGE);

        let local = request_hello_verification_with(|| false, 42, "Unlock Wormhole");
        assert!(!local.verified);
        assert_eq!(local.message, WINRT_HELLO_GAP);
    }

    #[test]
    fn verification_never_echoes_caller_message_or_claims_success() {
        let secret_prompt = "Unlock with hunter2-super-secret";
        let remote = request_hello_verification_with(|| true, 0, secret_prompt);
        let local = request_hello_verification_with(|| false, 1, secret_prompt);
        for v in [&remote, &local] {
            assert!(!v.verified);
            assert!(!v.message.contains("hunter2"));
            assert!(!format!("{v}").contains("hunter2"));
            assert!(!format!("{v:?}").contains("hunter2"));
        }
        // Production entry points also fail closed (never verified=true).
        let prod = request_hello_verification(0, secret_prompt);
        assert!(!prod.verified);
        assert!(
            prod.message == REMOTE_DESKTOP_UNAVAILABLE_MESSAGE
                || prod.message == WINRT_HELLO_GAP
        );
        let avail = check_hello_availability();
        assert!(!avail.available);
    }

    #[test]
    fn sessionname_short_or_non_rdp_prefix_is_local() {
        assert!(!is_remote_desktop_session_with(|_| 0, |_| Some("RDP".into())));
        assert!(!is_remote_desktop_session_with(|_| 0, |_| Some("Console".into())));
        assert!(!is_remote_desktop_session_with(|_| 0, |_| Some("".into())));
        assert!(!is_remote_desktop_session_with(|_| 0, |_| None));
    }

    #[test]
    fn display_impls_surface_fixed_ui_copy_only() {
        let a = HelloAvailability::new(false, WINRT_HELLO_GAP);
        let v = HelloVerification::new(false, REMOTE_DESKTOP_UNAVAILABLE_MESSAGE);
        let a_disp = format!("{a}");
        let v_disp = format!("{v}");
        let a_dbg = format!("{a:?}");
        let v_dbg = format!("{v:?}");
        assert!(a_disp.contains(WINRT_HELLO_GAP));
        assert!(a_disp.contains("unavailable"));
        assert!(v_disp.contains(REMOTE_DESKTOP_UNAVAILABLE_MESSAGE));
        assert!(v_disp.contains("rejected"));
        // Struct Debug/Display show the configured UI message fields only — never
        // invent caller prompt / biometric material that was not supplied.
        assert!(!a_disp.contains("hunter2") && !a_dbg.contains("hunter2"));
        assert!(!v_disp.contains("super-secret") && !v_dbg.contains("super-secret"));
    }

    #[test]
    fn fake_hello_prompt_scripted_without_ui() {
        let fake = FakeHelloPrompt::with_outcomes(
            HelloAvailability::new(true, "fake-available"),
            HelloVerification::new(true, "fake-verified"),
        );
        let a = fake.check_availability();
        assert!(a.available);
        assert_eq!(a.message, "fake-available");
        let v = fake.request_verification(1, "Unlock with hunter2-biometric");
        assert!(v.verified);
        assert_eq!(v.message, "fake-verified");
        assert_eq!(fake.availability_calls(), 1);
        assert_eq!(fake.verification_calls(), 1);
        // Caller prompt must never appear in Debug / result message.
        // Debug must also omit freeform scripted messages (bools + counts only).
        let dbg = format!("{fake:?}");
        assert!(!dbg.contains("hunter2"));
        assert!(!dbg.contains("biometric"));
        assert!(!dbg.contains("fake-available"));
        assert!(!dbg.contains("fake-verified"));
        assert!(dbg.contains("availability_available: true"));
        assert!(dbg.contains("verification_verified: true"));
        assert!(!v.message.contains("hunter2"));
    }

    #[test]
    fn fake_default_is_fail_closed_winrt_gap() {
        let fake = FakeHelloPrompt::default();
        assert!(!fake.check_availability().available);
        assert_eq!(fake.check_availability().message, WINRT_HELLO_GAP);
        assert!(!fake.request_verification(0, "Unlock").verified);
        assert_eq!(
            fake.request_verification(0, "Unlock").message,
            WINRT_HELLO_GAP
        );
    }

    #[test]
    fn fake_winrt_gap_and_remote_match_production_copy() {
        let gap = FakeHelloPrompt::winrt_gap();
        assert!(!gap.check_availability().available);
        assert_eq!(gap.check_availability().message, WINRT_HELLO_GAP);
        assert!(!gap.request_verification(0, "x").verified);
        assert_eq!(gap.request_verification(0, "x").message, WINRT_HELLO_GAP);

        let remote = FakeHelloPrompt::remote_session();
        assert!(!remote.check_availability().available);
        assert_eq!(
            remote.check_availability().message,
            REMOTE_DESKTOP_UNAVAILABLE_MESSAGE
        );
        assert!(!remote.request_verification(0, "secret-pin").verified);
        let dbg = format!("{remote:?}");
        assert!(!dbg.contains("secret-pin"));
        // Debug omits remote UI copy strings as well (flags only).
        assert!(!dbg.contains("Remote Desktop"));
        assert!(dbg.contains("availability_available: false"));
        assert!(dbg.contains("verification_verified: false"));
    }

    #[test]
    fn stub_hello_prompt_fail_closed_via_traits() {
        let stub = StubHelloPrompt;
        let a: HelloAvailability = AvailabilityProbe::check_availability(&stub);
        assert!(!a.available);
        assert!(
            a.message == WINRT_HELLO_GAP || a.message == REMOTE_DESKTOP_UNAVAILABLE_MESSAGE
        );
        let v = HelloPrompt::request_verification(&stub, 0, "Unlock with hunter2");
        assert!(!v.verified);
        assert!(!v.message.contains("hunter2"));
        assert!(!format!("{v:?}").contains("hunter2"));
        // Production stub never claims success regardless of HWND / prompt.
        let v2 = HelloPrompt::request_verification(&stub, isize::MAX, "");
        assert!(!v2.verified);
        assert!(
            v2.message == WINRT_HELLO_GAP || v2.message == REMOTE_DESKTOP_UNAVAILABLE_MESSAGE
        );
    }

    #[test]
    fn fake_set_outcomes_updates_without_retaining_prompt() {
        let fake = FakeHelloPrompt::winrt_gap();
        fake.set_availability(HelloAvailability::new(
            false,
            "custom-unavailable-with-secretish-token",
        ));
        fake.set_verification(HelloVerification::new(
            false,
            "custom-rejected-with-secretish-token",
        ));
        assert_eq!(
            fake.check_availability().message,
            "custom-unavailable-with-secretish-token"
        );
        let secret = "biometric-template-xyz";
        let v = fake.request_verification(99, secret);
        assert_eq!(v.message, "custom-rejected-with-secretish-token");
        let dbg = format!("{fake:?}");
        assert!(!dbg.contains(secret));
        assert!(!dbg.contains("secretish-token"));
        assert!(!dbg.contains("custom-unavailable"));
        assert!(!dbg.contains("custom-rejected"));
        assert!(!format!("{v}").contains(secret));
    }
}
