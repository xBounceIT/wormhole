//! Tunnel OTP prompt UI glue — no GPUI / ContentDialog chrome.
//!
//! Wires the existing [`wormhole_tunnels::ChannelOtpPrompt`] (provider side) to a
//! request/response Fake on the UI side. Tunnel establish calls
//! [`wormhole_tunnels::request_otp`] / [`wormhole_tunnels::OtpPrompt::prompt`]; the
//! host (or [`FakeOtpPromptUi`]) drains [`PendingOtpPrompt`] and replies Submit /
//! Cancel over the oneshot.
//!
//! Mirrors C# `DialogOtpPromptService` **transport** shape without WinUI (C# dialog
//! disables Submit on whitespace; this glue still accepts a Submitted empty code so
//! [`request_otp`] can reject it as `TunnelError::Establish`). Fail-closed map:
//! - user Cancel / Fake `None` / exhausted script / pending or channel abandon →
//!   [`TunnelError::Cancelled`]
//! - Submitted empty / whitespace-only → [`TunnelError::Establish`] (never echoes the
//!   code)
//!
//! Never log OTP codes — [`FakeOtpPromptUi`] [`Debug`] redacts queued script values.

use std::collections::VecDeque;
use std::fmt;
use std::sync::Arc;

use tokio::sync::mpsc;
use wormhole_tunnels::{
    ChannelOtpPrompt, OtpCode, OtpPromptError, OtpPromptRequest, OtpPromptResponse,
    PendingOtpPrompt, SharedOtpPrompt,
};

/// Open a provider-facing [`ChannelOtpPrompt`] and the UI-facing pending receiver.
///
/// Until [`OtpPromptChannel::open`] (or [`ChannelOtpPrompt::open_channel`]) the channel
/// prompt auto-cancels (fail closed), matching Null / no-UI behaviour.
pub struct OtpPromptChannel {
    prompt: Arc<ChannelOtpPrompt>,
    pending_rx: mpsc::UnboundedReceiver<PendingOtpPrompt>,
}

impl OtpPromptChannel {
    /// Create a channel-backed prompt and arm the UI listener.
    pub fn open() -> Self {
        let prompt = Arc::new(ChannelOtpPrompt::new());
        let pending_rx = prompt.open_channel();
        Self { prompt, pending_rx }
    }

    /// Provider / establish handle (`&dyn OtpPrompt` / DI).
    pub fn shared(&self) -> SharedOtpPrompt {
        Arc::clone(&self.prompt) as SharedOtpPrompt
    }

    /// Borrow the concrete channel prompt (prompt counts, set_auto_cancel, …).
    pub fn prompt(&self) -> &ChannelOtpPrompt {
        &self.prompt
    }

    /// UI-facing pending queue (one [`PendingOtpPrompt`] per `prompt` call).
    pub fn pending_rx(&mut self) -> &mut mpsc::UnboundedReceiver<PendingOtpPrompt> {
        &mut self.pending_rx
    }

    /// Detach the shared prompt (e.g. inject into a provider) while keeping the receiver.
    pub fn into_parts(
        self,
    ) -> (
        SharedOtpPrompt,
        mpsc::UnboundedReceiver<PendingOtpPrompt>,
    ) {
        (self.shared(), self.pending_rx)
    }
}

impl fmt::Debug for OtpPromptChannel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OtpPromptChannel")
            .field("prompt", &self.prompt)
            .field("pending_rx", &"<mpsc>")
            .finish()
    }
}

/// Submit a code on a pending prompt (UI Submit / Enter).
///
/// Does not trim — [`request_otp`] trims and rejects empty. Never log `code`.
pub fn submit_pending(pending: PendingOtpPrompt, code: impl Into<String>) -> bool {
    pending
        .respond
        .send(OtpPromptResponse::Submitted(OtpCode::new(code)))
        .is_ok()
}

/// User dismiss / Cancel on a pending prompt (fail closed at `request_otp`).
pub fn cancel_pending(pending: PendingOtpPrompt) -> bool {
    pending.respond.send(OtpPromptResponse::Cancelled).is_ok()
}

/// Scripted UI responder for [`ChannelOtpPrompt`] / [`OtpPromptChannel`] tests.
///
/// Each [`answer_next`](FakeOtpPromptUi::answer_next) dequeues one scripted outcome and
/// replies on the pending oneshot. Exhausted / empty script → Cancel (fail closed).
///
/// [`Debug`] redacts queued codes (`[REDACTED]`).
#[derive(Default)]
pub struct FakeOtpPromptUi {
    script: VecDeque<Option<String>>,
    answered: usize,
    last_request: Option<OtpPromptRequest>,
}

impl fmt::Debug for FakeOtpPromptUi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let redacted: Vec<Option<&'static str>> = self
            .script
            .iter()
            .map(|slot| match slot {
                Some(code) if code.is_empty() => Some(""),
                Some(_) => Some("[REDACTED]"),
                None => None,
            })
            .collect();
        f.debug_struct("FakeOtpPromptUi")
            .field("script", &redacted)
            .field("answered", &self.answered)
            .field("last_request", &self.last_request)
            .finish()
    }
}

impl FakeOtpPromptUi {
    pub fn new() -> Self {
        Self::default()
    }

    /// Queue submit codes and optional cancels (`None` = user dismiss).
    pub fn from_codes<S: Into<String>>(codes: impl IntoIterator<Item = Option<S>>) -> Self {
        let mut ui = Self::new();
        for code in codes {
            ui.push(code.map(Into::into));
        }
        ui
    }

    /// All entries are submitted codes (no cancels).
    pub fn from_submitted(codes: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self::from_codes(codes.into_iter().map(|c| Some(c)))
    }

    pub fn push(&mut self, code: Option<String>) {
        self.script.push_back(code);
    }

    pub fn answered_count(&self) -> usize {
        self.answered
    }

    pub fn last_request(&self) -> Option<&OtpPromptRequest> {
        self.last_request.as_ref()
    }

    /// Wait for one pending prompt and answer from the script (or cancel if exhausted).
    ///
    /// Returns the request metadata (never includes the OTP). Errors if the channel closed
    /// before a pending arrived.
    pub async fn answer_next(
        &mut self,
        rx: &mut mpsc::UnboundedReceiver<PendingOtpPrompt>,
    ) -> Result<OtpPromptRequest, OtpPromptError> {
        let pending = rx.recv().await.ok_or(OtpPromptError::ChannelClosed)?;
        let request = pending.request.clone();
        self.last_request = Some(request.clone());
        self.answered += 1;
        match self.script.pop_front() {
            Some(Some(code)) => {
                let _ = submit_pending(pending, code);
            }
            Some(None) | None => {
                let _ = cancel_pending(pending);
            }
        }
        Ok(request)
    }
}

/// Alias used in tests — same type as [`FakeOtpPromptUi`].
pub type FakePrompt = FakeOtpPromptUi;

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use wormhole_tunnels::{request_otp, request_second_factor, TunnelError};

    #[tokio::test]
    async fn channel_submit_via_fake_ui() {
        let mut channel = OtpPromptChannel::open();
        let mut ui = FakeOtpPromptUi::from_submitted(["  424242  "]);

        let prompt = channel.shared();
        let task = tokio::spawn(async move {
            request_otp(prompt.as_ref(), "Stormshield OTP — lab", "Enter code.").await
        });

        let req = ui.answer_next(channel.pending_rx()).await.unwrap();
        assert!(req.title.contains("Stormshield"));
        let code = task.await.unwrap().unwrap();
        assert_eq!(code.as_str(), "424242");
        assert_eq!(ui.answered_count(), 1);
        assert!(!format!("{code:?}").contains("424242"));
        assert!(!format!("{ui:?}").contains("424242"));
    }

    #[tokio::test]
    async fn channel_cancel_via_fake_ui_fail_closed() {
        let mut channel = OtpPromptChannel::open();
        let mut ui = FakeOtpPromptUi::from_codes([None::<&str>]);

        let prompt = channel.shared();
        let task = tokio::spawn(async move { request_otp(prompt.as_ref(), "t", "s").await });

        ui.answer_next(channel.pending_rx()).await.unwrap();
        assert!(matches!(
            task.await.unwrap().unwrap_err(),
            TunnelError::Cancelled
        ));
    }

    #[tokio::test]
    async fn fake_ui_exhausted_script_cancels() {
        let mut channel = OtpPromptChannel::open();
        let mut ui = FakeOtpPromptUi::new(); // empty → cancel

        let prompt = channel.shared();
        let task = tokio::spawn(async move { request_otp(prompt.as_ref(), "t", "s").await });

        ui.answer_next(channel.pending_rx()).await.unwrap();
        assert!(matches!(
            task.await.unwrap().unwrap_err(),
            TunnelError::Cancelled
        ));
        assert_eq!(ui.answered_count(), 1);
    }

    #[tokio::test]
    async fn submit_and_cancel_helpers() {
        let mut channel = OtpPromptChannel::open();

        let prompt = channel.shared();
        let submit = tokio::spawn({
            let prompt = Arc::clone(&prompt);
            async move { request_otp(prompt.as_ref(), "Cisco 2FA", "Enter TOTP.").await }
        });
        let pending = channel.pending_rx().recv().await.unwrap();
        assert_eq!(pending.request.title, "Cisco 2FA");
        assert!(submit_pending(pending, "totp-1"));
        assert_eq!(submit.await.unwrap().unwrap().as_str(), "totp-1");

        let cancel = tokio::spawn({
            let prompt = Arc::clone(&prompt);
            async move { request_otp(prompt.as_ref(), "t", "s").await }
        });
        let pending = channel.pending_rx().recv().await.unwrap();
        assert!(cancel_pending(pending));
        assert!(matches!(
            cancel.await.unwrap().unwrap_err(),
            TunnelError::Cancelled
        ));
    }

    #[tokio::test]
    async fn whitespace_otp_fails_without_echo() {
        let mut channel = OtpPromptChannel::open();
        let mut ui = FakePrompt::from_submitted(["   "]);

        let prompt = channel.shared();
        let task = tokio::spawn(async move { request_otp(prompt.as_ref(), "t", "s").await });
        ui.answer_next(channel.pending_rx()).await.unwrap();
        let err = task.await.unwrap().unwrap_err();
        let rendered = format!("{err}");
        assert!(rendered.contains("empty"), "{rendered}");
        assert!(!rendered.contains("   "));
    }

    #[test]
    fn fake_ui_debug_redacts_queued_codes() {
        let ui = FakeOtpPromptUi::from_codes([Some("112233"), None, Some("")]);
        let dbg = format!("{ui:?}");
        assert!(!dbg.contains("112233"), "{dbg}");
        assert!(dbg.contains("[REDACTED]"), "{dbg}");
        assert!(dbg.contains("None"), "{dbg}");
    }

    #[tokio::test]
    async fn pending_drop_maps_to_cancelled() {
        let mut channel = OtpPromptChannel::open();
        let prompt = channel.shared();
        let task = tokio::spawn(async move { request_otp(prompt.as_ref(), "t", "s").await });
        let pending = channel.pending_rx().recv().await.unwrap();
        drop(pending);
        assert!(matches!(
            task.await.unwrap().unwrap_err(),
            TunnelError::Cancelled
        ));
    }

    #[tokio::test]
    async fn into_parts_keeps_request_response() {
        let channel = OtpPromptChannel::open();
        let (shared, mut rx) = channel.into_parts();
        let mut ui = FakeOtpPromptUi::from_submitted(["998877"]);

        let task = tokio::spawn(async move {
            request_second_factor(
                shared.as_ref(),
                OtpPromptRequest::new("Watchguard 2FA — lab", "Enter code or 'p'."),
            )
            .await
        });
        let req = ui.answer_next(&mut rx).await.unwrap();
        assert!(req.title.contains("Watchguard"));
        assert_eq!(task.await.unwrap().unwrap().as_str(), "998877");
    }

    #[tokio::test]
    async fn empty_string_submit_is_establish_not_cancelled() {
        // C# ContentDialog blocks Primary on whitespace; transport still maps Submitted("")
        // through request_otp → Establish (distinct from Cancelled).
        let mut channel = OtpPromptChannel::open();
        let mut ui = FakeOtpPromptUi::from_submitted([""]);

        let prompt = channel.shared();
        let task = tokio::spawn(async move { request_otp(prompt.as_ref(), "t", "s").await });
        ui.answer_next(channel.pending_rx()).await.unwrap();
        let err = task.await.unwrap().unwrap_err();
        assert!(
            matches!(err, TunnelError::Establish(_)),
            "expected Establish, got {err:?}"
        );
        let rendered = format!("{err}");
        assert!(rendered.contains("empty"), "{rendered}");
        assert!(!matches!(err, TunnelError::Cancelled));
    }

    #[tokio::test]
    async fn drop_pending_rx_maps_to_cancelled() {
        let channel = OtpPromptChannel::open();
        let prompt = channel.shared();
        // Drop the UI receiver (abandon channel) while keeping the shared prompt.
        drop(channel);
        let err = request_otp(prompt.as_ref(), "t", "s").await.unwrap_err();
        assert!(matches!(err, TunnelError::Cancelled));
    }

    #[tokio::test]
    async fn fake_ui_multi_step_submit_then_cancel() {
        let mut channel = OtpPromptChannel::open();
        let mut ui = FakeOtpPromptUi::from_codes([Some("112233"), None]);

        let prompt = channel.shared();
        let first = tokio::spawn({
            let prompt = Arc::clone(&prompt);
            async move { request_otp(prompt.as_ref(), "a", "b").await }
        });
        ui.answer_next(channel.pending_rx()).await.unwrap();
        assert_eq!(first.await.unwrap().unwrap().as_str(), "112233");

        let second = tokio::spawn({
            let prompt = Arc::clone(&prompt);
            async move { request_otp(prompt.as_ref(), "c", "d").await }
        });
        ui.answer_next(channel.pending_rx()).await.unwrap();
        assert!(matches!(
            second.await.unwrap().unwrap_err(),
            TunnelError::Cancelled
        ));
        assert_eq!(ui.answered_count(), 2);
    }

    #[tokio::test]
    async fn shared_plus_pending_rx_is_the_join_pattern() {
        // request_otp lives on SharedOtpPrompt — pending_rx needs &mut self, so the
        // channel does not expose &self async helpers that would conflict with answering.
        let mut channel = OtpPromptChannel::open();
        let mut ui = FakeOtpPromptUi::from_submitted(["aabbcc"]);
        let prompt = channel.shared();
        let task = tokio::spawn(async move {
            request_otp(prompt.as_ref(), "Conv", "sub").await
        });
        let req = ui.answer_next(channel.pending_rx()).await.unwrap();
        assert_eq!(req.title, "Conv");
        assert_eq!(task.await.unwrap().unwrap().as_str(), "aabbcc");
    }

    #[tokio::test]
    async fn submit_pending_false_when_provider_abandoned() {
        let mut channel = OtpPromptChannel::open();
        let prompt = channel.shared();
        let task = tokio::spawn(async move { request_otp(prompt.as_ref(), "t", "s").await });
        let pending = channel.pending_rx().recv().await.unwrap();
        // Abort the waiter so the oneshot receiver drops before UI submit.
        task.abort();
        // Yield so the aborted task can drop respond_rx.
        tokio::task::yield_now().await;
        assert!(!submit_pending(pending, "too-late"));
    }
}
