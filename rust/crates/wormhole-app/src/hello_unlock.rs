//! Windows Hello unlock prompt UI glue — no GPUI / no live WinRT.
//!
//! Mirrors `MainWindow.TryUnlockWithWindowsHelloAsync`: check availability, then
//! request verification, then map to lock-overlay outcomes. Production wires
//! [`StubHelloPrompt`] (always fail-closed). Tests use [`FakeHelloUnlockUi`]
//! (scripted Success / Cancelled / Unavailable) or [`HelloUnlockGlue`] over
//! [`FakeHelloPrompt`].
//!
//! **Never** retain or log biometric material, PIN/password fallbacks, or caller
//! prompt strings that may embed secrets. [`FakeHelloUnlockUi`] / glue [`Debug`]
//! expose outcome kinds + call counts only.

use std::collections::VecDeque;
use std::fmt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use wormhole_secrets_win::{
    AvailabilityProbe, FakeHelloPrompt, HelloAvailability, HelloPrompt, HelloVerification,
    StubHelloPrompt, WINRT_HELLO_GAP,
};

/// Default prompt shown to `UserConsentVerifier` (C# `"Unlock Wormhole"`).
pub const DEFAULT_UNLOCK_PROMPT: &str = "Unlock Wormhole";

/// Lock-overlay status while Hello is in progress (C# `LockMessageText`).
pub const WAITING_FOR_HELLO: &str = "Waiting for Windows Hello.";

/// C# `UserConsentVerificationResult.Verified` message.
pub const HELLO_VERIFIED_MESSAGE: &str = "Verified.";

/// C# `UserConsentVerificationResult.Canceled` message.
pub const HELLO_CANCELED_MESSAGE: &str = "Windows Hello was canceled.";

/// C# `UserConsentVerifierAvailability.Available` message.
pub const HELLO_AVAILABLE_MESSAGE: &str = "Windows Hello is available.";

/// Coarse lock-overlay outcome after a Hello unlock attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HelloUnlockOutcome {
    /// User verified — host may call CompleteUnlock.
    Success,
    /// User dismissed / canceled Hello — show fallback with cancel copy.
    Cancelled,
    /// Unavailable (remote / WinRT gap / device / policy / Fake exhausted) — fallback.
    Unavailable,
}

impl HelloUnlockOutcome {
    /// Whether the lock overlay may dismiss (only Success).
    pub fn is_unlocked(self) -> bool {
        matches!(self, Self::Success)
    }
}

/// Result of [`HelloUnlockGlue::request_unlock`] / [`FakeHelloUnlockUi::request_unlock`].
///
/// `status_text` is UI-safe fixed copy from Hello / Fake — never biometric material.
#[derive(Clone, PartialEq, Eq)]
pub struct HelloUnlockResult {
    /// Coarse outcome.
    pub outcome: HelloUnlockOutcome,
    /// Status / InfoBar text (safe to show; never secrets).
    pub status_text: String,
}

impl HelloUnlockResult {
    /// Construct a result.
    pub fn new(outcome: HelloUnlockOutcome, status_text: impl Into<String>) -> Self {
        Self {
            outcome,
            status_text: status_text.into(),
        }
    }

    /// Whether unlock completed.
    pub fn is_unlocked(&self) -> bool {
        self.outcome.is_unlocked()
    }
}

impl fmt::Debug for HelloUnlockResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // status_text is fixed UI copy by contract; still avoid dumping freeform
        // strings that a mis-scripted Fake might hold — kind only in Debug.
        f.debug_struct("HelloUnlockResult")
            .field("outcome", &self.outcome)
            .field("status_text_len", &self.status_text.len())
            .finish()
    }
}

impl fmt::Display for HelloUnlockResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({:?})", self.status_text, self.outcome)
    }
}

/// Combined Hello probe + prompt for DI (both traits on one object).
pub trait HelloUnlockSource: AvailabilityProbe + HelloPrompt {}

impl<T: AvailabilityProbe + HelloPrompt> HelloUnlockSource for T {}

/// Shared Hello source for the unlock glue.
pub type SharedHelloUnlockSource = Arc<dyn HelloUnlockSource + Send + Sync>;

/// Thin glue: availability → verification → [`HelloUnlockOutcome`] (C# unlock button).
///
/// Fail-closed: Stub / WinRT gap / remote / unverified non-cancel →
/// [`HelloUnlockOutcome::Unavailable`]. Only `verified: true` yields Success.
pub struct HelloUnlockGlue {
    source: SharedHelloUnlockSource,
    calls: AtomicUsize,
}

impl fmt::Debug for HelloUnlockGlue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HelloUnlockGlue")
            .field("calls", &self.calls.load(Ordering::SeqCst))
            .field("source", &"<HelloUnlockSource>")
            .finish()
    }
}

impl HelloUnlockGlue {
    /// Glue over an injected Hello source.
    pub fn new(source: SharedHelloUnlockSource) -> Self {
        Self {
            source,
            calls: AtomicUsize::new(0),
        }
    }

    /// Production stub — always Unavailable (`WINRT_HELLO_GAP` or remote message).
    pub fn with_stub() -> Self {
        Self::new(Arc::new(StubHelloPrompt) as SharedHelloUnlockSource)
    }

    /// Test harness: Fake Hello prompt (default fail-closed WinRT gap).
    pub fn with_fake() -> (Self, Arc<FakeHelloPrompt>) {
        let fake = Arc::new(FakeHelloPrompt::winrt_gap());
        let glue = Self::new(Arc::clone(&fake) as SharedHelloUnlockSource);
        (glue, fake)
    }

    /// How many times [`Self::request_unlock`] was called.
    pub fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    /// Request Hello unlock (check availability, then verification).
    ///
    /// `owner_hwnd` / `message` mirror C# `RequestVerificationAsync` and are
    /// forwarded to the prompt — never retained on this glue.
    ///
    /// Hosts should serialize calls (C# `_lockHelloInProgress`) — this glue does
    /// not debounce overlapping unlock attempts.
    pub fn request_unlock(&self, owner_hwnd: isize, message: &str) -> HelloUnlockResult {
        self.calls.fetch_add(1, Ordering::SeqCst);

        let availability = self.source.check_availability();
        if !availability.available {
            return HelloUnlockResult::new(HelloUnlockOutcome::Unavailable, availability.message);
        }

        let verification = self.source.request_verification(owner_hwnd, message);
        map_verification(verification)
    }
}

/// Map a verification result to lock-overlay outcomes (C# `IsVerified` / fallback).
///
/// Cancelled is detected only via exact [`HELLO_CANCELED_MESSAGE`] parity with
/// C# `UserConsentVerificationResult.Canceled` copy — other rejections are
/// Unavailable (fail closed for unlock). `verified: true` always wins.
fn map_verification(verification: HelloVerification) -> HelloUnlockResult {
    if verification.verified {
        return HelloUnlockResult::new(HelloUnlockOutcome::Success, verification.message);
    }
    if verification.message == HELLO_CANCELED_MESSAGE {
        return HelloUnlockResult::new(HelloUnlockOutcome::Cancelled, verification.message);
    }
    HelloUnlockResult::new(HelloUnlockOutcome::Unavailable, verification.message)
}

/// Scripted unlock UI for tests (no WinRT, no biometric, no HelloPrompt).
///
/// Each [`request_unlock`](FakeHelloUnlockUi::request_unlock) dequeues one scripted
/// outcome. Exhausted / empty script → [`HelloUnlockOutcome::Unavailable`] (fail closed).
///
/// [`Debug`] exposes queued outcome kinds + call counts only — never prompt strings.
#[derive(Default)]
pub struct FakeHelloUnlockUi {
    script: Mutex<VecDeque<HelloUnlockOutcome>>,
    calls: AtomicUsize,
}

impl fmt::Debug for FakeHelloUnlockUi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let queued: Vec<HelloUnlockOutcome> = self
            .script
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .copied()
            .collect();
        f.debug_struct("FakeHelloUnlockUi")
            .field("queued", &queued)
            .field("calls", &self.calls.load(Ordering::SeqCst))
            .finish()
    }
}

impl FakeHelloUnlockUi {
    /// Empty script (fail-closed Unavailable until outcomes are pushed).
    pub fn new() -> Self {
        Self::default()
    }

    /// Single-outcome Fake.
    pub fn with_outcome(outcome: HelloUnlockOutcome) -> Self {
        Self::with_script([outcome])
    }

    /// Multi-step script.
    pub fn with_script(outcomes: impl IntoIterator<Item = HelloUnlockOutcome>) -> Self {
        Self {
            script: Mutex::new(outcomes.into_iter().collect()),
            calls: AtomicUsize::new(0),
        }
    }

    /// Queue a single Success (C# verified copy). One-shot — further calls fail closed.
    pub fn success() -> Self {
        Self::with_outcome(HelloUnlockOutcome::Success)
    }

    /// Queue a single Cancelled (C# cancel copy). One-shot — further calls fail closed.
    pub fn cancelled() -> Self {
        Self::with_outcome(HelloUnlockOutcome::Cancelled)
    }

    /// Queue a single Unavailable (WinRT gap copy). One-shot — further calls fail closed.
    pub fn unavailable() -> Self {
        Self::with_outcome(HelloUnlockOutcome::Unavailable)
    }

    fn script_guard(&self) -> std::sync::MutexGuard<'_, VecDeque<HelloUnlockOutcome>> {
        self.script.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Queue another outcome (FIFO).
    pub fn push(&self, outcome: HelloUnlockOutcome) {
        self.script_guard().push_back(outcome);
    }

    /// How many unlock requests were made.
    pub fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    /// Remaining scripted outcomes.
    pub fn remaining(&self) -> usize {
        self.script_guard().len()
    }

    /// Request unlock — pops script or Unavailable. Never retains `message`.
    pub fn request_unlock(&self, owner_hwnd: isize, message: &str) -> HelloUnlockResult {
        let _ = (owner_hwnd, message);
        self.calls.fetch_add(1, Ordering::SeqCst);
        let outcome = self
            .script_guard()
            .pop_front()
            .unwrap_or(HelloUnlockOutcome::Unavailable);
        HelloUnlockResult::new(outcome, status_text_for(outcome))
    }
}

fn status_text_for(outcome: HelloUnlockOutcome) -> &'static str {
    match outcome {
        HelloUnlockOutcome::Success => HELLO_VERIFIED_MESSAGE,
        HelloUnlockOutcome::Cancelled => HELLO_CANCELED_MESSAGE,
        HelloUnlockOutcome::Unavailable => WINRT_HELLO_GAP,
    }
}

/// Configure a [`FakeHelloPrompt`] for a scripted unlock path (glue tests).
pub fn fake_prompt_for_outcome(outcome: HelloUnlockOutcome) -> FakeHelloPrompt {
    match outcome {
        HelloUnlockOutcome::Success => FakeHelloPrompt::with_outcomes(
            HelloAvailability::new(true, HELLO_AVAILABLE_MESSAGE),
            HelloVerification::new(true, HELLO_VERIFIED_MESSAGE),
        ),
        HelloUnlockOutcome::Cancelled => FakeHelloPrompt::with_outcomes(
            HelloAvailability::new(true, HELLO_AVAILABLE_MESSAGE),
            HelloVerification::new(false, HELLO_CANCELED_MESSAGE),
        ),
        HelloUnlockOutcome::Unavailable => FakeHelloPrompt::winrt_gap(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wormhole_secrets_win::REMOTE_DESKTOP_UNAVAILABLE_MESSAGE;

    #[test]
    fn stub_glue_fail_closed_unavailable() {
        let glue = HelloUnlockGlue::with_stub();
        let r = glue.request_unlock(0, "Unlock with hunter2-biometric");
        assert_eq!(r.outcome, HelloUnlockOutcome::Unavailable);
        assert!(!r.is_unlocked());
        assert!(
            r.status_text == WINRT_HELLO_GAP
                || r.status_text == REMOTE_DESKTOP_UNAVAILABLE_MESSAGE
        );
        assert!(!r.status_text.contains("hunter2"));
        assert!(!format!("{r:?}").contains("hunter2"));
        assert!(!format!("{glue:?}").contains("hunter2"));
        assert_eq!(glue.calls(), 1);
    }

    #[test]
    fn glue_maps_success_cancel_unavailable() {
        let success = HelloUnlockGlue::new(Arc::new(fake_prompt_for_outcome(
            HelloUnlockOutcome::Success,
        )) as SharedHelloUnlockSource);
        let r = success.request_unlock(1, DEFAULT_UNLOCK_PROMPT);
        assert_eq!(r.outcome, HelloUnlockOutcome::Success);
        assert_eq!(r.status_text, HELLO_VERIFIED_MESSAGE);
        assert!(r.is_unlocked());

        let cancel = HelloUnlockGlue::new(Arc::new(fake_prompt_for_outcome(
            HelloUnlockOutcome::Cancelled,
        )) as SharedHelloUnlockSource);
        let r = cancel.request_unlock(1, DEFAULT_UNLOCK_PROMPT);
        assert_eq!(r.outcome, HelloUnlockOutcome::Cancelled);
        assert_eq!(r.status_text, HELLO_CANCELED_MESSAGE);
        assert!(!r.is_unlocked());

        let (gap, _) = HelloUnlockGlue::with_fake();
        let r = gap.request_unlock(0, "secret-prompt");
        assert_eq!(r.outcome, HelloUnlockOutcome::Unavailable);
        assert_eq!(r.status_text, WINRT_HELLO_GAP);
        assert!(!format!("{r:?}").contains("secret-prompt"));
    }

    #[test]
    fn glue_unavailable_skips_verification_when_probe_fails() {
        let fake = Arc::new(FakeHelloPrompt::with_outcomes(
            HelloAvailability::new(false, "No Windows Hello device is present."),
            HelloVerification::new(true, HELLO_VERIFIED_MESSAGE), // must not be used
        ));
        let glue = HelloUnlockGlue::new(Arc::clone(&fake) as SharedHelloUnlockSource);
        let r = glue.request_unlock(42, DEFAULT_UNLOCK_PROMPT);
        assert_eq!(r.outcome, HelloUnlockOutcome::Unavailable);
        assert_eq!(r.status_text, "No Windows Hello device is present.");
        assert!(!r.is_unlocked());
        assert_eq!(fake.availability_calls(), 1);
        assert_eq!(
            fake.verification_calls(),
            0,
            "probe failure must not invoke verification"
        );
    }

    #[test]
    fn glue_maps_non_cancel_rejection_to_unavailable() {
        // C# rejection copy (busy / device / retries / generic) → Unavailable, not Cancelled.
        for message in [
            "Windows Hello is busy.",
            "No Windows Hello device is present.",
            "Windows Hello retries were exhausted.",
            "Windows Hello verification failed.",
            "Windows Hello is unavailable.",
            "",
            "Windows Hello was canceled",   // missing trailing '.'
            "Windows Hello was canceled. ", // trailing space
            "windows hello was canceled.",  // case drift
        ] {
            let fake = FakeHelloPrompt::with_outcomes(
                HelloAvailability::new(true, HELLO_AVAILABLE_MESSAGE),
                HelloVerification::new(false, message),
            );
            let glue = HelloUnlockGlue::new(Arc::new(fake) as SharedHelloUnlockSource);
            let r = glue.request_unlock(1, DEFAULT_UNLOCK_PROMPT);
            assert_eq!(
                r.outcome,
                HelloUnlockOutcome::Unavailable,
                "non-cancel rejection must be Unavailable: {message:?}"
            );
            assert_eq!(r.status_text, message);
            assert!(!r.is_unlocked());
        }

        // verified: true wins even if message looks like cancel copy.
        let spoof = FakeHelloPrompt::with_outcomes(
            HelloAvailability::new(true, HELLO_AVAILABLE_MESSAGE),
            HelloVerification::new(true, HELLO_CANCELED_MESSAGE),
        );
        let glue = HelloUnlockGlue::new(Arc::new(spoof) as SharedHelloUnlockSource);
        let r = glue.request_unlock(1, DEFAULT_UNLOCK_PROMPT);
        assert_eq!(r.outcome, HelloUnlockOutcome::Success);
        assert!(r.is_unlocked());
    }

    #[test]
    fn fake_ui_scripts_success_cancel_unavailable() {
        let ui = FakeHelloUnlockUi::with_script([
            HelloUnlockOutcome::Success,
            HelloUnlockOutcome::Cancelled,
            HelloUnlockOutcome::Unavailable,
        ]);
        assert_eq!(
            ui.request_unlock(0, "hunter2").outcome,
            HelloUnlockOutcome::Success
        );
        assert_eq!(
            ui.request_unlock(0, "hunter2").outcome,
            HelloUnlockOutcome::Cancelled
        );
        assert_eq!(
            ui.request_unlock(0, "hunter2").outcome,
            HelloUnlockOutcome::Unavailable
        );
        // Exhausted → fail-closed Unavailable.
        let exhausted = ui.request_unlock(0, "hunter2");
        assert_eq!(exhausted.outcome, HelloUnlockOutcome::Unavailable);
        assert_eq!(exhausted.status_text, WINRT_HELLO_GAP);
        assert_eq!(ui.calls(), 4);
        let dbg = format!("{ui:?}");
        assert!(!dbg.contains("hunter2"));
        assert!(dbg.contains("calls: 4"));
    }

    #[test]
    fn fake_ui_constructors_and_push() {
        assert!(FakeHelloUnlockUi::success()
            .request_unlock(0, "")
            .is_unlocked());
        assert_eq!(
            FakeHelloUnlockUi::cancelled()
                .request_unlock(0, "")
                .outcome,
            HelloUnlockOutcome::Cancelled
        );
        assert_eq!(
            FakeHelloUnlockUi::unavailable()
                .request_unlock(0, "")
                .outcome,
            HelloUnlockOutcome::Unavailable
        );
        // Constructors are one-shot scripts (not sticky like FakeHelloPrompt).
        let once = FakeHelloUnlockUi::success();
        assert!(once.request_unlock(0, "").is_unlocked());
        let exhausted = once.request_unlock(0, "secret");
        assert_eq!(exhausted.outcome, HelloUnlockOutcome::Unavailable);
        assert_eq!(exhausted.status_text, WINRT_HELLO_GAP);
        assert!(!format!("{once:?}").contains("secret"));
        let ui = FakeHelloUnlockUi::new();
        assert_eq!(ui.remaining(), 0);
        ui.push(HelloUnlockOutcome::Success);
        assert_eq!(ui.remaining(), 1);
        assert!(ui.request_unlock(0, DEFAULT_UNLOCK_PROMPT).is_unlocked());
        assert_eq!(ui.remaining(), 0);
    }

    #[test]
    fn fake_ui_debug_never_retains_prompt() {
        let ui = FakeHelloUnlockUi::success();
        let secret = "biometric-template-xyz";
        let r = ui.request_unlock(99, secret);
        assert_eq!(r.status_text, HELLO_VERIFIED_MESSAGE);
        let dbg = format!("{ui:?}");
        assert!(!dbg.contains(secret));
        assert!(!dbg.contains("biometric"));
        assert!(!format!("{r:?}").contains(secret));
        // Result Debug redacts status_text body (length only).
        assert!(!format!("{r:?}").contains("Verified"));
        assert!(format!("{r:?}").contains("status_text_len"));
    }

    #[test]
    fn outcome_display_and_waiting_copy() {
        assert_eq!(WAITING_FOR_HELLO, "Waiting for Windows Hello.");
        assert_eq!(DEFAULT_UNLOCK_PROMPT, "Unlock Wormhole");
        let r = HelloUnlockResult::new(HelloUnlockOutcome::Cancelled, HELLO_CANCELED_MESSAGE);
        let disp = format!("{r}");
        assert!(disp.contains(HELLO_CANCELED_MESSAGE));
        assert!(disp.contains("Cancelled"));
    }
}
