//! Windows Hello consent glue — availability probe + remote gate + consent UI.
//!
//! Composes the existing [`crate::hello::AvailabilityProbe`] (availability gate,
//! incl. the WinRT gap) with an injectable consent-prompt seam ([`HelloConsentUi`]
//! / [`FakeHelloConsentUi`] / [`HelloConsentChannel`]) and a remote-session
//! detector seam ([`RemoteSessionDetector`] / [`FakeRemoteSessionDetector`], C#
//! `SM_REMOTESESSION`). C# oracle: `Services/Security/WindowsHelloService.cs`
//! (`CheckAvailabilityAsync` + `RequestVerificationAsync`) and
//! `Services/Security/RemoteDesktopSessionDetector.cs`.
//!
//! | Condition | [`HelloConsentResult`] |
//! |---|---|
//! | remote session detected | **denied** (`REMOTE_DESKTOP_UNAVAILABLE_MESSAGE`); consent UI never consulted |
//! | availability probe → `available == false` (C# `DeviceBusy` / not-present / disabled-by-policy / not-configured / catch-all "unavailable", incl. WinRT probe errors) | **denied** (probe message); consent UI never consulted; never fail-open to a weaker auth |
//! | availability probe OK + UI `Confirm` | granted |
//! | availability probe OK + UI `Cancel` / UI error / channel abandon | **denied** (`HELLO_CONSENT_CANCELED_MESSAGE`) |
//!
//! The probe surface is boolean-only ([`crate::hello::AvailabilityProbe`] has no
//! error channel; C# collapses WinRT failures to `unavailable`), so "availability
//! probe error" is represented by an unavailable probe — the glue treats **every**
//! `available == false` result as a denial and never consults the consent UI.
//!
//! Interactive WinRT `UserConsentVerifier` is **not** wired ([`crate::hello::WINRT_HELLO_GAP`]);
//! this glue is the decision layer a future WinRT consent slot plugs into, and
//! hosts must not treat a denial as authorization to fall back to a weaker unlock
//! (PIN/password) without user consent.
//!
//! **Never** log biometric / PIN material or caller prompt strings that may embed
//! secrets. This module holds status labels and boolean choices only; [`Debug`]
//! exposes counts and booleans — never freeform message fields or retained prompts.

use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};

use crate::hello::{
    AvailabilityProbe, REMOTE_DESKTOP_UNAVAILABLE_MESSAGE,
};

/// Fixed copy when consent grants (C# `UserConsentVerificationResult.Verified → "Verified."`).
pub const HELLO_CONSENT_CONFIRMED_MESSAGE: &str = "Windows Hello consent granted.";

/// Fixed copy when the consent UI cancels (C# `...Canceled → "Windows Hello was canceled."`).
pub const HELLO_CONSENT_CANCELED_MESSAGE: &str = "Windows Hello was canceled.";

/// Outcome of a single consent prompt: either an explicit Confirm or a Cancel.
///
/// Any non-confirm outcome (Cancel, UI error, abandoned channel) is treated as
/// consent **denied** by [`HelloConsentGlue`] — never fail-open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HelloConsentChoice {
    /// The user explicitly granted consent (C# `UserConsentVerificationResult.Verified`).
    Confirmed,
    /// The user dismissed / the prompt errored / the prompt was abandoned.
    Canceled,
}

/// Result of a Hello consent decision.
///
/// `message` is fixed UI copy only — it never contains caller prompt strings or
/// biometric / PIN material. [`Debug`] exposes `granted` + `message` length only
/// (module invariant: Debug never carries freeform message fields).
#[derive(Clone, PartialEq, Eq)]
pub struct HelloConsentResult {
    /// Whether consent was granted (only via an explicit UI Confirm when the
    /// remote + availability gates pass).
    pub granted: bool,
    /// Human-readable reason (safe to show in UI).
    pub message: String,
}

impl fmt::Debug for HelloConsentResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HelloConsentResult")
            .field("granted", &self.granted)
            .field("message_len", &self.message.len())
            .finish()
    }
}

impl HelloConsentResult {
    /// Convenience constructor.
    pub fn new(granted: bool, message: impl Into<String>) -> Self {
        Self {
            granted,
            message: message.into(),
        }
    }
}

impl fmt::Display for HelloConsentResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} ({})",
            self.message,
            if self.granted { "granted" } else { "denied" }
        )
    }
}

/// Detect a remote desktop session (`SM_REMOTESESSION` / `SESSIONNAME=RDP-*`).
///
/// C# parity: `Services/Security/RemoteDesktopSessionDetector.cs`. Production
/// wraps [`crate::hello::is_remote_desktop_session`]; tests inject
/// [`FakeRemoteSessionDetector`].
pub trait RemoteSessionDetector: Send + Sync {
    /// Whether the current session is a remote desktop session.
    fn is_remote_desktop_session(&self) -> bool;
}

/// Scripted remote-session detector for unit tests (no Win32 metrics / env).
///
/// [`Debug`] exposes the scripted flag only.
pub struct FakeRemoteSessionDetector {
    remote: AtomicBool,
}

impl fmt::Debug for FakeRemoteSessionDetector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FakeRemoteSessionDetector")
            .field("remote", &self.remote.load(Ordering::SeqCst))
            .finish()
    }
}

impl FakeRemoteSessionDetector {
    /// Start remote (`true`) or local (`false`).
    pub fn new(remote: bool) -> Self {
        Self {
            remote: AtomicBool::new(remote),
        }
    }

    /// Remote-session fake (C# detector returns true).
    pub fn remote_session() -> Self {
        Self::new(true)
    }

    /// Local-session fake (C# detector returns false).
    pub fn local_session() -> Self {
        Self::new(false)
    }

    /// Re-script the detector.
    pub fn set_remote(&self, remote: bool) {
        self.remote.store(remote, Ordering::SeqCst);
    }

    /// Current scripted value (parity with the trait surface).
    pub fn is_remote(&self) -> bool {
        self.remote.load(Ordering::SeqCst)
    }
}

impl RemoteSessionDetector for FakeRemoteSessionDetector {
    fn is_remote_desktop_session(&self) -> bool {
        self.is_remote()
    }
}

/// Injectable Hello consent prompt (C# `UserConsentVerifier` consent dialog).
///
/// Implementations must **not** write biometric / PIN material or the caller
/// `message` (may embed secrets) to logs. Any non-confirm outcome is treated as
/// consent denied by [`HelloConsentGlue`].
pub trait HelloConsentUi: Send + Sync {
    /// Prompt the user; `owner_hwnd` / `message` mirror C# API parity.
    fn request_consent(&self, owner_hwnd: isize, message: &str) -> HelloConsentChoice;
}

/// Scripted consent UI for unit tests (no WinRT, no biometric UI).
///
/// Configure Confirm / Cancel explicitly. Call counts are tracked; the last
/// consent `message` is **not** retained. [`Debug`] exposes booleans + counts —
/// never freeform messages (avoids secret echo in harness logs / panic output).
pub struct FakeHelloConsentUi {
    choice: Mutex<HelloConsentChoice>,
    consent_calls: AtomicUsize,
}

impl Default for FakeHelloConsentUi {
    fn default() -> Self {
        Self::cancel()
    }
}

impl fmt::Debug for FakeHelloConsentUi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FakeHelloConsentUi")
            .field("choice", &*self.choice_guard())
            .field("consent_calls", &self.consent_calls.load(Ordering::SeqCst))
            .finish()
    }
}

impl FakeHelloConsentUi {
    fn choice_guard(&self) -> std::sync::MutexGuard<'_, HelloConsentChoice> {
        self.choice.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// UI that always confirms.
    pub fn confirm() -> Self {
        Self::with_choice(HelloConsentChoice::Confirmed)
    }

    /// UI that always cancels (default / fail-closed).
    pub fn cancel() -> Self {
        Self::with_choice(HelloConsentChoice::Canceled)
    }

    /// Explicit scripted choice.
    pub fn with_choice(choice: HelloConsentChoice) -> Self {
        Self {
            choice: Mutex::new(choice),
            consent_calls: AtomicUsize::new(0),
        }
    }

    /// Re-script the next consent outcome.
    pub fn set_choice(&self, choice: HelloConsentChoice) {
        *self.choice_guard() = choice;
    }

    /// How many times [`HelloConsentUi::request_consent`] was called.
    pub fn consent_calls(&self) -> usize {
        self.consent_calls.load(Ordering::SeqCst)
    }
}

impl HelloConsentUi for FakeHelloConsentUi {
    fn request_consent(&self, owner_hwnd: isize, message: &str) -> HelloConsentChoice {
        let _ = (owner_hwnd, message); // never retain — may embed secrets
        self.consent_calls.fetch_add(1, Ordering::SeqCst);
        *self.choice_guard()
    }
}

/// Consent glue: remote gate → availability probe → injectable consent UI.
///
/// Fail-closed table (module header): remote session or an unavailable probe
/// denies **before** the consent UI runs; only an explicit UI Confirm grants.
pub struct HelloConsentGlue<P, R, U>
where
    P: AvailabilityProbe,
    R: RemoteSessionDetector,
    U: HelloConsentUi,
{
    probe: P,
    remote: R,
    ui: U,
    consent_calls: AtomicUsize,
}

impl<P, R, U> fmt::Debug for HelloConsentGlue<P, R, U>
where
    P: AvailabilityProbe,
    R: RemoteSessionDetector,
    U: HelloConsentUi,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Counts only — never dump probe/UI script internals or freeform messages.
        f.debug_struct("HelloConsentGlue")
            .field("consent_calls", &self.consent_calls.load(Ordering::SeqCst))
            .finish()
    }
}

impl<P, R, U> HelloConsentGlue<P, R, U>
where
    P: AvailabilityProbe,
    R: RemoteSessionDetector,
    U: HelloConsentUi,
{
    /// Construct with injectable availability probe, remote detector, and consent UI.
    pub fn new(probe: P, remote: R, ui: U) -> Self {
        Self {
            probe,
            remote,
            ui,
            consent_calls: AtomicUsize::new(0),
        }
    }

    /// How many times [`request_consent`](Self::request_consent) ran.
    pub fn consent_calls(&self) -> usize {
        self.consent_calls.load(Ordering::SeqCst)
    }

    /// Decide Hello consent.
    ///
    /// 1. Remote session → denied (C# disables Hello remotely; UI never runs).
    /// 2. Availability probe unavailable → denied with the probe's message (C#
    ///    collapses WinRT probe failures here; UI never runs — never fail-open).
    /// 3. Otherwise the consent UI decides: Confirm → granted, Cancel → denied.
    pub fn request_consent(&self, owner_hwnd: isize, message: &str) -> HelloConsentResult {
        self.consent_calls.fetch_add(1, Ordering::SeqCst);

        if self.remote.is_remote_desktop_session() {
            return HelloConsentResult::new(false, REMOTE_DESKTOP_UNAVAILABLE_MESSAGE);
        }

        let availability = self.probe.check_availability();
        if !availability.available {
            return HelloConsentResult::new(false, availability.message);
        }

        match self.ui.request_consent(owner_hwnd, message) {
            HelloConsentChoice::Confirmed => {
                HelloConsentResult::new(true, HELLO_CONSENT_CONFIRMED_MESSAGE)
            }
            HelloConsentChoice::Canceled => {
                HelloConsentResult::new(false, HELLO_CONSENT_CANCELED_MESSAGE)
            }
        }
    }
}

/// A pending consent prompt awaiting a UI response.
///
/// Destination of one [`ChannelHelloConsentUi::request_consent`] call. The UI
/// side receives it, then calls [`confirm`](Self::confirm) or
/// [`cancel`](Self::cancel). Dropping without answering → consent denied
/// (fail closed). `message` is the caller prompt (may embed secrets) — keep it
/// out of logs / `Debug`.
pub struct PendingHelloConsent {
    /// Caller prompt (may embed secrets; do not log / retain in Debug).
    pub message: String,
    respond: mpsc::Sender<HelloConsentChoice>,
}

impl PendingHelloConsent {
    /// Reply Confirm; `false` if the consent caller already abandoned.
    pub fn confirm(self) -> bool {
        self.respond.send(HelloConsentChoice::Confirmed).is_ok()
    }

    /// Reply Cancel (fail closed); `false` if the consent caller already abandoned.
    pub fn cancel(self) -> bool {
        self.respond.send(HelloConsentChoice::Canceled).is_ok()
    }
}

/// Channel-backed consent UI (mirrors the `OtpPromptChannel` shape with
/// `std::sync::mpsc` — no async runtime needed; blocked until the UI answers).
///
/// `request_consent` sends a [`PendingHelloConsent`] and blocks for a
/// Confirm / Cancel reply. If the pending queue receiver is dropped or the
/// pending is dropped unanswered, consent fails closed (denied).
pub struct ChannelHelloConsentUi {
    tx: mpsc::Sender<PendingHelloConsent>,
}

impl fmt::Debug for ChannelHelloConsentUi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChannelHelloConsentUi")
            .field("tx", &"<mpsc>")
            .finish_non_exhaustive()
    }
}

impl HelloConsentUi for ChannelHelloConsentUi {
    fn request_consent(&self, _owner_hwnd: isize, message: &str) -> HelloConsentChoice {
        let (respond_tx, respond_rx) = mpsc::channel();
        let pending = PendingHelloConsent {
            message: message.to_owned(),
            respond: respond_tx,
        };
        if self.tx.send(pending).is_err() {
            // UI receiver abandoned → deny.
            return HelloConsentChoice::Canceled;
        }
        respond_rx
            .recv()
            .unwrap_or(HelloConsentChoice::Canceled)
    }
}

impl HelloConsentUi for Arc<ChannelHelloConsentUi> {
    fn request_consent(&self, owner_hwnd: isize, message: &str) -> HelloConsentChoice {
        self.as_ref().request_consent(owner_hwnd, message)
    }
}

/// Open provider-facing [`ChannelHelloConsentUi`] + the UI-facing pending queue.
///
/// Join pattern (mirrors `OtpPromptChannel`): `shared()` goes to the glue, the
/// UI drains `pending_rx` / [`PendingHelloConsent::confirm`] /
/// [`PendingHelloConsent::cancel`].
pub struct HelloConsentChannel {
    shared: Arc<ChannelHelloConsentUi>,
    pending_rx: mpsc::Receiver<PendingHelloConsent>,
}

impl fmt::Debug for HelloConsentChannel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HelloConsentChannel")
            .field("pending_rx", &"<mpsc>")
            .finish()
    }
}

impl HelloConsentChannel {
    /// Create a channel-backed consent UI and arm the UI listener.
    pub fn open() -> Self {
        let (tx, pending_rx) = mpsc::channel();
        Self {
            shared: Arc::new(ChannelHelloConsentUi { tx }),
            pending_rx,
        }
    }

    /// Shared consent handle (implements [`HelloConsentUi`]).
    pub fn shared(&self) -> Arc<ChannelHelloConsentUi> {
        Arc::clone(&self.shared)
    }

    /// UI-facing pending queue (one [`PendingHelloConsent`] per request).
    pub fn pending_rx(&mut self) -> &mut mpsc::Receiver<PendingHelloConsent> {
        &mut self.pending_rx
    }

    /// Detach the shared handle while keeping the receiver.
    pub fn into_parts(
        self,
    ) -> (
        Arc<ChannelHelloConsentUi>,
        mpsc::Receiver<PendingHelloConsent>,
    ) {
        (self.shared, self.pending_rx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hello::{
        FakeHelloPrompt, HelloAvailability, HelloVerification, StubHelloPrompt, WINRT_HELLO_GAP,
    };

    fn available_probe() -> FakeHelloPrompt {
        FakeHelloPrompt::with_outcomes(
            HelloAvailability::new(true, "fake-available"),
            HelloVerification::new(true, "fake-verified"),
        )
    }

    #[test]
    fn local_available_ui_confirm_granted() {
        let glue = HelloConsentGlue::new(
            available_probe(),
            FakeRemoteSessionDetector::local_session(),
            FakeHelloConsentUi::confirm(),
        );
        let result = glue.request_consent(0, "Unlock Wormhole");
        assert!(result.granted);
        assert_eq!(result.message, HELLO_CONSENT_CONFIRMED_MESSAGE);
        assert_eq!(glue.consent_calls(), 1);
    }

    #[test]
    fn local_available_ui_cancel_denied() {
        let glue = HelloConsentGlue::new(
            available_probe(),
            FakeRemoteSessionDetector::local_session(),
            FakeHelloConsentUi::cancel(),
        );
        let result = glue.request_consent(1, "Unlock Wormhole");
        assert!(!result.granted);
        assert_eq!(result.message, HELLO_CONSENT_CANCELED_MESSAGE);
        assert_eq!(glue.consent_calls(), 1);
    }

    #[test]
    fn remote_session_denied_before_ui_runs() {
        let glue = HelloConsentGlue::new(
            available_probe(),
            FakeRemoteSessionDetector::remote_session(),
            FakeHelloConsentUi::confirm(),
        );
        let result = glue.request_consent(0, "secret-prompt");
        assert!(!result.granted);
        assert_eq!(result.message, REMOTE_DESKTOP_UNAVAILABLE_MESSAGE);
    }

    #[test]
    fn remote_wins_over_availability_and_ui() {
        // C# CheckAvailabilityAsync checks the remote gate first, so the remote
        // message wins even when the probe would report a different unavailability.
        let glue = HelloConsentGlue::new(
            FakeHelloPrompt::with_outcomes(
                HelloAvailability::new(false, "fake-busy"),
                HelloVerification::new(false, "fake-busy"),
            ),
            FakeRemoteSessionDetector::remote_session(),
            FakeHelloConsentUi::confirm(),
        );
        let result = glue.request_consent(0, "x");
        assert!(!result.granted);
        assert_eq!(result.message, REMOTE_DESKTOP_UNAVAILABLE_MESSAGE);
    }

    #[test]
    fn unavailable_probe_denied_even_when_ui_confirms() {
        // Fail-closed ordering: availability denial happens before the consent UI
        // is consulted — an explicit Confirm must not override an unavailable probe.
        let ui = FakeHelloConsentUi::confirm();
        let glue = HelloConsentGlue::new(
            FakeHelloPrompt::with_outcomes(
                HelloAvailability::new(false, "no Hello device present"),
                HelloVerification::new(false, "no Hello device present"),
            ),
            FakeRemoteSessionDetector::local_session(),
            ui,
        );
        let result = glue.request_consent(0, "Unlock");
        assert!(!result.granted);
        assert_eq!(result.message, "no Hello device present");
        assert_eq!(glue.consent_calls(), 1);
    }

    #[test]
    fn probe_error_shaped_unavailable_is_denied_never_fail_open() {
        // The probe surface is boolean-only (C# collapses WinRT probe failures to
        // `available == false`) — every unavailable probe maps to a denial and the
        // UI is never consulted (never fail-open to weaker auth silently).
        let glue = HelloConsentGlue::new(
            FakeHelloPrompt::with_outcomes(
                HelloAvailability::new(false, "Windows Hello is unavailable."),
                HelloVerification::new(false, "Windows Hello is unavailable."),
            ),
            FakeRemoteSessionDetector::local_session(),
            FakeHelloConsentUi::confirm(),
        );
        let result = glue.request_consent(0, "Unlock");
        assert!(!result.granted);
        assert_eq!(result.message, "Windows Hello is unavailable.");
    }

    #[test]
    fn fail_closed_ordering_remote_over_availability_over_ui() {
        // Deliberately poignant: each earlier gate denies regardless of the UI.
        for (probe_available, remote, expected_granted) in
            [(false, false, false), (true, true, false), (false, true, false)]
        {
            let glue = HelloConsentGlue::new(
                FakeHelloPrompt::with_outcomes(
                    HelloAvailability::new(probe_available, "probe"),
                    HelloVerification::new(probe_available, "probe"),
                ),
                FakeRemoteSessionDetector::new(remote),
                FakeHelloConsentUi::confirm(),
            );
            let result = glue.request_consent(0, "Unlock");
            assert_eq!(result.granted, expected_granted, "matrix {probe_available}/{remote}");
        }
    }

    #[test]
    fn remote_detector_scripted_and_debug() {
        let detector = FakeRemoteSessionDetector::remote_session();
        assert!(detector.is_remote());
        detector.set_remote(false);
        assert!(!detector.is_remote());
        assert!(!format!("{detector:?}").contains("hunter2"));
        assert!(format!("{detector:?}").contains("remote: false"));
    }

    #[test]
    fn fake_consent_ui_counts_and_debug_never_echo_prompt() {
        let ui = FakeHelloConsentUi::confirm();
        assert_eq!(ui.consent_calls(), 0);
        assert_eq!(ui.request_consent(5, "hunter2-promise"), HelloConsentChoice::Confirmed);
        assert_eq!(ui.consent_calls(), 1);
        ui.set_choice(HelloConsentChoice::Canceled);
        assert_eq!(ui.request_consent(5, "hunter2-promise"), HelloConsentChoice::Canceled);
        assert_eq!(ui.consent_calls(), 2);
        let dbg = format!("{ui:?}");
        assert!(!dbg.contains("hunter2"));
        assert!(!dbg.contains("promise"));
        assert!(dbg.contains("consent_calls: 2"));
        // Default fake cancels (fail closed).
        assert_eq!(FakeHelloConsentUi::default().request_consent(0, "x"), HelloConsentChoice::Canceled);
    }

    #[test]
    fn result_and_debug_are_fixed_status_labels_only() {
        let granted = HelloConsentResult::new(true, HELLO_CONSENT_CONFIRMED_MESSAGE);
        let denied = HelloConsentResult::new(false, HELLO_CONSENT_CANCELED_MESSAGE);
        assert!(format!("{granted}").contains("granted"));
        assert!(format!("{denied}").contains("denied"));
        for r in [&granted, &denied] {
            let dbg = format!("{r:?}");
            assert!(!dbg.contains("hunter2"));
            assert!(!dbg.contains("biometric"));
        }
        // Display never embeds caller prompts.
        assert!(!format!("{denied}").contains("hunter2"));
    }

    #[test]
    fn result_debug_never_exposes_freeform_message() {
        // A hostile / buggy probe could surface a secret-shaped message through
        // the denial path — Debug must never carry it (Display is the UI channel
        // and stays intact for fixed copy).
        let hostile = HelloConsentResult::new(false, "hunter2-secret-message");
        let dbg = format!("{hostile:?}");
        assert!(!dbg.contains("hunter2"));
        assert!(!dbg.contains("secret-message"));
        assert!(dbg.contains("message_len"));
        assert!(dbg.contains("granted"));
        // Display remains the user-facing channel (fixed copy only in practice).
        assert!(format!("{hostile}").contains("denied"));
        assert!(format!("{hostile}").contains("hunter2-secret-message"));
    }

    #[test]
    fn stub_probe_via_glue_fails_closed_locally() {
        // Production-ish wiring: StubHelloPrompt reports WINRT_HELLO_GAP →
        // unavailable → denied even though the UI would confirm.
        let glue = HelloConsentGlue::new(
            StubHelloPrompt,
            FakeRemoteSessionDetector::local_session(),
            FakeHelloConsentUi::confirm(),
        );
        let result = glue.request_consent(0, "Unlock with hunter2-biometric");
        assert!(!result.granted);
        assert_eq!(result.message, WINRT_HELLO_GAP);
        assert!(!format!("{result}").contains("hunter2"));
        assert!(!format!("{result:?}").contains("hunter2"));
    }

    #[test]
    fn channel_confirm_roundtrip_granted() {
        let channel = HelloConsentChannel::open();
        let (shared, rx) = channel.into_parts();
        let glue = HelloConsentGlue::new(
            available_probe(),
            FakeRemoteSessionDetector::local_session(),
            shared,
        );
        let answerer = std::thread::spawn(move || {
            let pending = rx.recv().expect("pending consent");
            assert_eq!(pending.message, "Unlock Wormhole");
            assert!(pending.confirm());
        });
        let result = glue.request_consent(0, "Unlock Wormhole");
        answerer.join().expect("ui thread");
        assert!(result.granted);
        assert_eq!(result.message, HELLO_CONSENT_CONFIRMED_MESSAGE);
    }

    #[test]
    fn channel_cancel_roundtrip_denied() {
        let mut channel = HelloConsentChannel::open();
        let glue = HelloConsentGlue::new(
            available_probe(),
            FakeRemoteSessionDetector::local_session(),
            channel.shared(),
        );
        let answerer = std::thread::spawn(move || {
            let pending = channel.pending_rx().recv().expect("pending");
            assert!(pending.cancel());
        });
        let result = glue.request_consent(0, "Unlock");
        answerer.join().expect("ui thread");
        assert!(!result.granted);
        assert_eq!(result.message, HELLO_CONSENT_CANCELED_MESSAGE);
    }

    #[test]
    fn channel_abandon_and_drop_fail_closed() {
        // Dropping the responder without answering → denied.
        let channel = HelloConsentChannel::open();
        let (shared, rx) = channel.into_parts();
        let gutted = HelloConsentGlue::new(
            available_probe(),
            FakeRemoteSessionDetector::local_session(),
            shared,
        );
        let drop_it = std::thread::spawn(move || {
            let pending = rx.recv().expect("pending");
            drop(pending); // abandon — no reply
        });
        let result = gutted.request_consent(0, "Unlock");
        drop_it.join().expect("ui thread");
        assert!(!result.granted);
        assert_eq!(result.message, HELLO_CONSENT_CANCELED_MESSAGE);

        // Dropping the whole channel (receiver gone) → request cannot send → denied.
        let channel = HelloConsentChannel::open();
        let shared = channel.shared();
        drop(channel); // pending_rx dropped
        let gutted2 = HelloConsentGlue::new(
            available_probe(),
            FakeRemoteSessionDetector::local_session(),
            shared,
        );
        let result2 = gutted2.request_consent(0, "Unlock");
        assert!(!result2.granted);
        assert_eq!(result2.message, HELLO_CONSENT_CANCELED_MESSAGE);
    }

    #[test]
    fn channel_debug_redacts_message_never_shows_secrets() {
        // A pending request carries a secret-shaped prompt; Debug of the pending
        // struct (there is none — message is intentionally not Debug-able) and the
        // channel must never surface it.
        let mut channel = HelloConsentChannel::open();
        let shared = channel.shared();
        let caller = std::thread::spawn(move || {
            let ui = shared.as_ref();
            HelloConsentUi::request_consent(ui, 0, "hunter2-secret-promise")
        });
        let pending = channel.pending_rx().recv().expect("pending");
        assert_eq!(pending.message, "hunter2-secret-promise");
        let channel_dbg = format!("{channel:?}");
        assert!(!channel_dbg.contains("hunter2"));
        assert!(!channel_dbg.contains("promise"));
        // Confirm so the caller unblocks and we can observe a granted result free
        // of any secret material.
        pending.confirm();
        let choice = caller.join().expect("caller thread");
        assert_eq!(choice, HelloConsentChoice::Confirmed);
        // Glue-level Debug is counts-only.
        let glue = HelloConsentGlue::new(
            available_probe(),
            FakeRemoteSessionDetector::local_session(),
            FakeHelloConsentUi::confirm(),
        );
        let _ = glue.request_consent(0, "hunter2-secret-promise");
        let glue_dbg = format!("{glue:?}");
        assert!(!glue_dbg.contains("hunter2"));
        assert!(glue_dbg.contains("consent_calls"));
    }
}
