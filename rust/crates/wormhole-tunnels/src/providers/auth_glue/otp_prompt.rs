//! OTP / second-factor prompt stub (UI-independent).
//!
//! Mirrors C# [`IOtpPromptService`](../../../../../../Services/Tunneling/IOtpPromptService.cs):
//! providers request a one-time code mid-connect; the UI (or test harness) responds.
//!
//! **Wiring today:** WatchGuard / Stormshield / Fortinet portal or pre-auth loops are
//! not yet ported — call [`request_second_factor`] / [`request_otp`] from those paths
//! when they land. Cisco aggregate-auth prepare
//! (`crate::providers::cisco::aggregate_auth::prepare_cisco_sidecar_config` with
//! `CiscoSecondFactor::Prompt`) already calls [`request_second_factor`]. Sidecar
//! `establish` still takes already-resolved materials / stdin JSON and does **not**
//! invoke this prompt.
//!
//! Never log OTP codes. [`OtpCode`] / [`OtpPromptResponse`] / [`MemoryOtpPrompt`]
//! [`Debug`] (and [`OtpCode`] [`Display`]) redact values.

use std::collections::VecDeque;
use std::fmt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use tokio::sync::{mpsc, oneshot};

use super::redact_nonempty;
use crate::TunnelError;

/// One-time / second-factor code entered by the user.
///
/// [`Debug`] / [`Display`] never print the plaintext. Prefer [`OtpCode::into_inner`]
/// only at the auth-glue / sidecar stdin boundary (never pass into tracing fields).
#[derive(Clone, PartialEq, Eq)]
pub struct OtpCode(String);

impl OtpCode {
    /// Wrap a raw code (caller may still need to trim via [`request_otp`]).
    pub fn new(code: impl Into<String>) -> Self {
        Self(code.into())
    }

    /// Borrow the plaintext (do not log).
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume into the plaintext string (do not log).
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl fmt::Debug for OtpCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("OtpCode")
            .field(&redact_nonempty(&self.0))
            .finish()
    }
}

impl fmt::Display for OtpCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Display is also redacted — never print codes via `{}` either.
        f.write_str(redact_nonempty(&self.0))
    }
}

/// Prompt metadata shown to the user (no secrets).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OtpPromptRequest {
    pub title: String,
    pub subtitle: String,
}

impl OtpPromptRequest {
    pub fn new(title: impl Into<String>, subtitle: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            subtitle: subtitle.into(),
        }
    }
}

/// Outcome of a single prompt interaction (parity with C# `string?`).
///
/// - [`Submitted`](OtpPromptResponse::Submitted) — user clicked Submit (code may still
///   be empty/whitespace; [`request_otp`] rejects that).
/// - [`Cancelled`](OtpPromptResponse::Cancelled) — user dismissed the dialog (not a
///   panic / token cancel).
#[derive(Clone, PartialEq, Eq)]
pub enum OtpPromptResponse {
    Submitted(OtpCode),
    Cancelled,
}

impl fmt::Debug for OtpPromptResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Submitted(code) => f.debug_tuple("Submitted").field(code).finish(),
            Self::Cancelled => f.write_str("Cancelled"),
        }
    }
}

/// Errors from the prompt transport (not user dismiss).
#[derive(Debug, thiserror::Error)]
pub enum OtpPromptError {
    /// Caller cancellation token / shutdown (C# `OperationCanceledException`).
    #[error("OTP prompt cancelled")]
    Cancelled,
    /// Channel mode: no UI listener / receiver dropped.
    #[error("OTP prompt channel closed")]
    ChannelClosed,
}

/// UI-thread-aware (eventually) OTP prompt — mirrors C# `IOtpPromptService`.
///
/// Implementations must **never** write the entered code to logs or tracing.
#[async_trait]
pub trait OtpPrompt: Send + Sync {
    async fn prompt(&self, request: OtpPromptRequest) -> Result<OtpPromptResponse, OtpPromptError>;
}

/// Alias for second-factor / TOTP / push-selector prompts (same contract as [`OtpPrompt`]).
pub trait SecondFactorPrompt: OtpPrompt {}

impl<T: OtpPrompt + ?Sized> SecondFactorPrompt for T {}

/// Provider hook: request an OTP / second factor and return a trimmed non-empty code.
///
/// Maps:
/// - user dismiss → [`TunnelError::Cancelled`]
/// - empty/whitespace after trim → [`TunnelError::Establish`]
/// - transport cancel / closed → [`TunnelError::Cancelled`]
///
/// Never logs the code. Call from portal / pre-auth loops (WatchGuard, Stormshield, …)
/// when those are ported; sidecar `establish` paths do not call this yet.
pub async fn request_otp(
    prompt: &dyn OtpPrompt,
    title: impl Into<String>,
    subtitle: impl Into<String>,
) -> Result<OtpCode, TunnelError> {
    request_second_factor(prompt, OtpPromptRequest::new(title, subtitle)).await
}

/// Same as [`request_otp`] with an explicit [`OtpPromptRequest`].
pub async fn request_second_factor(
    prompt: &dyn OtpPrompt,
    request: OtpPromptRequest,
) -> Result<OtpCode, TunnelError> {
    // Title/subtitle are safe to debug; never attach a code field.
    tracing::debug!(
        title = %request.title,
        subtitle = %request.subtitle,
        "requesting OTP / second-factor prompt"
    );

    let response = prompt.prompt(request).await.map_err(|e| match e {
        OtpPromptError::Cancelled | OtpPromptError::ChannelClosed => TunnelError::Cancelled,
    })?;

    match response {
        OtpPromptResponse::Cancelled => Err(TunnelError::Cancelled),
        OtpPromptResponse::Submitted(code) => {
            let raw = code.into_inner();
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                return Err(TunnelError::Establish(
                    "OTP / second-factor prompt returned an empty code".into(),
                ));
            }
            Ok(OtpCode::new(trimmed))
        }
    }
}

/// Always returns user-cancel (`Ok(Cancelled)`). Useful as a fail-closed default
/// until a UI or test harness is attached.
#[derive(Debug, Default, Clone, Copy)]
pub struct NullOtpPrompt;

#[async_trait]
impl OtpPrompt for NullOtpPrompt {
    async fn prompt(&self, _request: OtpPromptRequest) -> Result<OtpPromptResponse, OtpPromptError> {
        Ok(OtpPromptResponse::Cancelled)
    }
}

/// Scripted / in-memory OTP prompt for unit tests (parity with C# `ScriptedOtpPrompt`).
///
/// Each [`prompt`](OtpPrompt::prompt) dequeues the next queued response. Queue empty →
/// user-cancel (`Cancelled`), matching C# “null when exhausted”.
///
/// [`Debug`] redacts queued codes (never dump the script plaintext).
#[derive(Default)]
pub struct MemoryOtpPrompt {
    script: Mutex<VecDeque<Option<String>>>,
    requests: Mutex<Vec<OtpPromptRequest>>,
    prompt_count: AtomicUsize,
}

impl fmt::Debug for MemoryOtpPrompt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let script = self.script.lock().unwrap_or_else(|p| p.into_inner());
        let redacted_script: Vec<Option<&str>> = script
            .iter()
            .map(|slot| match slot {
                Some(code) => Some(redact_nonempty(code)),
                None => None,
            })
            .collect();
        let requests = self.requests.lock().unwrap_or_else(|p| p.into_inner());
        f.debug_struct("MemoryOtpPrompt")
            .field("script", &redacted_script)
            .field("requests", &*requests)
            .field("prompt_count", &self.prompt_count.load(Ordering::SeqCst))
            .finish()
    }
}

impl MemoryOtpPrompt {
    pub fn new() -> Self {
        Self::default()
    }

    /// Queue submit codes and optional cancels (`None` = user dismiss).
    pub fn from_codes<S: Into<String>>(codes: impl IntoIterator<Item = Option<S>>) -> Self {
        let prompt = Self::new();
        for code in codes {
            prompt.push(code.map(Into::into));
        }
        prompt
    }

    /// Convenience: all entries are submitted codes (no cancels).
    pub fn from_submitted(codes: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self::from_codes(codes.into_iter().map(|c| Some(c)))
    }

    pub fn push(&self, code: Option<String>) {
        self.script
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push_back(code);
    }

    pub fn prompt_count(&self) -> usize {
        self.prompt_count.load(Ordering::SeqCst)
    }

    pub fn requests(&self) -> Vec<OtpPromptRequest> {
        self.requests
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }
}

#[async_trait]
impl OtpPrompt for MemoryOtpPrompt {
    async fn prompt(&self, request: OtpPromptRequest) -> Result<OtpPromptResponse, OtpPromptError> {
        self.prompt_count.fetch_add(1, Ordering::SeqCst);
        self.requests
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(request);
        let next = self
            .script
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .pop_front();
        match next {
            Some(Some(code)) => Ok(OtpPromptResponse::Submitted(OtpCode::new(code))),
            Some(None) | None => Ok(OtpPromptResponse::Cancelled),
        }
    }
}

/// Alias used in tests — same type as [`MemoryOtpPrompt`].
pub type FakeOtpPrompt = MemoryOtpPrompt;

#[derive(Debug)]
enum ChannelMode {
    /// Fail closed: behave like [`NullOtpPrompt`].
    AutoCancel,
    /// Forward to a UI / test consumer.
    Channel(mpsc::UnboundedSender<PendingOtpPrompt>),
}

/// Pending prompt waiting for a UI (or test) decision.
pub struct PendingOtpPrompt {
    pub request: OtpPromptRequest,
    pub respond: oneshot::Sender<OtpPromptResponse>,
}

impl fmt::Debug for PendingOtpPrompt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PendingOtpPrompt")
            .field("request", &self.request)
            .field("respond", &"<oneshot>")
            .finish()
    }
}

/// Channel-backed prompt for future UI wiring (independent of WinUI / GPUI).
///
/// Default mode is auto-cancel (fail closed). Tests / a future host call
/// [`open_channel`](ChannelOtpPrompt::open_channel) and answer via the oneshot.
#[derive(Debug)]
pub struct ChannelOtpPrompt {
    mode: Mutex<ChannelMode>,
    prompt_count: AtomicUsize,
}

impl Default for ChannelOtpPrompt {
    fn default() -> Self {
        Self::new()
    }
}

impl ChannelOtpPrompt {
    pub fn new() -> Self {
        Self {
            mode: Mutex::new(ChannelMode::AutoCancel),
            prompt_count: AtomicUsize::new(0),
        }
    }

    pub fn set_auto_cancel(&self) {
        *self.mode.lock().unwrap_or_else(|p| p.into_inner()) = ChannelMode::AutoCancel;
    }

    pub fn open_channel(&self) -> mpsc::UnboundedReceiver<PendingOtpPrompt> {
        let (tx, rx) = mpsc::unbounded_channel();
        *self.mode.lock().unwrap_or_else(|p| p.into_inner()) = ChannelMode::Channel(tx);
        rx
    }

    pub fn prompt_count(&self) -> usize {
        self.prompt_count.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl OtpPrompt for ChannelOtpPrompt {
    async fn prompt(&self, request: OtpPromptRequest) -> Result<OtpPromptResponse, OtpPromptError> {
        self.prompt_count.fetch_add(1, Ordering::SeqCst);
        let respond_rx = {
            let mode = self.mode.lock().unwrap_or_else(|p| p.into_inner());
            match &*mode {
                ChannelMode::AutoCancel => return Ok(OtpPromptResponse::Cancelled),
                ChannelMode::Channel(tx) => {
                    let (respond_tx, respond_rx) = oneshot::channel();
                    let pending = PendingOtpPrompt {
                        request,
                        respond: respond_tx,
                    };
                    if tx.send(pending).is_err() {
                        return Err(OtpPromptError::ChannelClosed);
                    }
                    respond_rx
                }
            }
        };
        respond_rx.await.map_err(|_| OtpPromptError::ChannelClosed)
    }
}

/// Shared handle type for DI / future provider fields.
pub type SharedOtpPrompt = Arc<dyn OtpPrompt>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn otp_code_debug_and_display_redact() {
        let code = OtpCode::new("123456");
        let dbg = format!("{code:?}");
        let disp = format!("{code}");
        assert!(dbg.contains("[REDACTED]"), "{dbg}");
        assert!(!dbg.contains("123456"), "{dbg}");
        assert_eq!(disp, "[REDACTED]");
        assert_eq!(code.as_str(), "123456");
        assert_eq!(format!("{:?}", OtpCode::new("")), "OtpCode(\"\")");
        assert_eq!(format!("{}", OtpCode::new("")), "");
    }

    #[test]
    fn otp_response_debug_redacts_submitted() {
        let resp = OtpPromptResponse::Submitted(OtpCode::new("999111"));
        let dbg = format!("{resp:?}");
        assert!(dbg.contains("[REDACTED]"), "{dbg}");
        assert!(!dbg.contains("999111"), "{dbg}");
    }

    #[test]
    fn memory_prompt_debug_redacts_queued_codes() {
        let prompt = MemoryOtpPrompt::from_codes([Some("112233"), None, Some("")]);
        let dbg = format!("{prompt:?}");
        assert!(!dbg.contains("112233"), "{dbg}");
        assert!(dbg.contains("[REDACTED]"), "{dbg}");
        // Cancel / empty slots stay visible as structure only.
        assert!(dbg.contains("None"), "{dbg}");
    }

    #[tokio::test]
    async fn memory_prompt_submit_then_cancel() {
        let prompt = MemoryOtpPrompt::from_codes([Some("112233"), None]);
        let r1 = prompt
            .prompt(OtpPromptRequest::new("t1", "s1"))
            .await
            .unwrap();
        match r1 {
            OtpPromptResponse::Submitted(code) => assert_eq!(code.as_str(), "112233"),
            OtpPromptResponse::Cancelled => panic!("expected submitted"),
        }
        let r2 = prompt
            .prompt(OtpPromptRequest::new("t2", "s2"))
            .await
            .unwrap();
        assert_eq!(r2, OtpPromptResponse::Cancelled);
        // Exhausted queue → cancel (C# ScriptedOtpPrompt).
        let r3 = prompt
            .prompt(OtpPromptRequest::new("t3", "s3"))
            .await
            .unwrap();
        assert_eq!(r3, OtpPromptResponse::Cancelled);
        assert_eq!(prompt.prompt_count(), 3);
        assert_eq!(prompt.requests().len(), 3);
    }

    #[tokio::test]
    async fn request_otp_returns_trimmed_code() {
        let prompt = FakeOtpPrompt::from_submitted(["  424242  "]);
        let code = request_otp(&prompt, "Stormshield OTP — lab", "Enter the one-time code.")
            .await
            .unwrap();
        assert_eq!(code.as_str(), "424242");
        assert_eq!(prompt.prompt_count(), 1);
        let req = &prompt.requests()[0];
        assert!(req.title.contains("Stormshield"));
        assert!(!format!("{code:?}").contains("424242"));
    }

    #[tokio::test]
    async fn request_otp_user_cancel() {
        let prompt = MemoryOtpPrompt::from_codes([None::<&str>]);
        let err = request_second_factor(
            &prompt,
            OtpPromptRequest::new("Watchguard 2FA — x", "Enter code or 'p'."),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, TunnelError::Cancelled));
    }

    #[tokio::test]
    async fn request_otp_empty_after_trim_fails() {
        let prompt = MemoryOtpPrompt::from_submitted(["   "]);
        let err = request_otp(&prompt, "t", "s").await.unwrap_err();
        let rendered = format!("{err}");
        assert!(rendered.contains("empty"), "{rendered}");
        assert!(!rendered.contains("   "));
    }

    #[tokio::test]
    async fn request_otp_empty_string_fails() {
        let prompt = MemoryOtpPrompt::from_submitted([""]);
        let err = request_otp(&prompt, "t", "s").await.unwrap_err();
        match err {
            TunnelError::Establish(msg) => {
                assert!(msg.contains("empty"), "{msg}");
            }
            other => panic!("expected Establish, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn null_prompt_always_cancels() {
        // Fail-closed default: no UI → user-cancel (not an establish success path).
        let direct = NullOtpPrompt
            .prompt(OtpPromptRequest::new("t", "s"))
            .await
            .unwrap();
        assert_eq!(direct, OtpPromptResponse::Cancelled);
        let err = request_otp(&NullOtpPrompt, "t", "s")
            .await
            .unwrap_err();
        assert!(matches!(err, TunnelError::Cancelled));
    }

    #[tokio::test]
    async fn channel_prompt_request_response_cancel() {
        let prompt = Arc::new(ChannelOtpPrompt::new());
        let mut rx = prompt.open_channel();

        let submit = tokio::spawn({
            let prompt = Arc::clone(&prompt);
            async move {
                request_otp(
                    prompt.as_ref(),
                    "Cisco 2FA",
                    "Enter secondary password / TOTP.",
                )
                .await
            }
        });

        let pending = rx.recv().await.expect("pending prompt");
        assert_eq!(pending.request.title, "Cisco 2FA");
        pending
            .respond
            .send(OtpPromptResponse::Submitted(OtpCode::new("totp-1")))
            .unwrap();
        assert_eq!(submit.await.unwrap().unwrap().as_str(), "totp-1");

        let cancel = tokio::spawn({
            let prompt = Arc::clone(&prompt);
            async move { request_otp(prompt.as_ref(), "t", "s").await }
        });
        let pending = rx.recv().await.expect("pending cancel");
        pending
            .respond
            .send(OtpPromptResponse::Cancelled)
            .unwrap();
        assert!(matches!(
            cancel.await.unwrap().unwrap_err(),
            TunnelError::Cancelled
        ));
    }

    #[tokio::test]
    async fn channel_auto_cancel_before_open() {
        let prompt = ChannelOtpPrompt::new();
        let err = request_otp(&prompt, "t", "s").await.unwrap_err();
        assert!(matches!(err, TunnelError::Cancelled));
        assert_eq!(prompt.prompt_count(), 1);
    }

    #[tokio::test]
    async fn channel_closed_when_receiver_dropped() {
        let prompt = ChannelOtpPrompt::new();
        let rx = prompt.open_channel();
        drop(rx);
        let err = prompt
            .prompt(OtpPromptRequest::new("t", "s"))
            .await
            .unwrap_err();
        assert!(matches!(err, OtpPromptError::ChannelClosed));
    }

    #[tokio::test]
    async fn channel_pending_drop_maps_to_cancelled() {
        let prompt = Arc::new(ChannelOtpPrompt::new());
        let mut rx = prompt.open_channel();
        let task = tokio::spawn({
            let prompt = Arc::clone(&prompt);
            async move { request_otp(prompt.as_ref(), "t", "s").await }
        });
        let pending = rx.recv().await.expect("pending");
        drop(pending); // UI abandoned the oneshot without responding
        assert!(matches!(
            task.await.unwrap().unwrap_err(),
            TunnelError::Cancelled
        ));
    }

    #[tokio::test]
    async fn channel_set_auto_cancel_fail_closed_again() {
        let prompt = ChannelOtpPrompt::new();
        let rx = prompt.open_channel();
        drop(rx);
        prompt.set_auto_cancel();
        let err = request_otp(&prompt, "t", "s").await.unwrap_err();
        assert!(matches!(err, TunnelError::Cancelled));
    }
}
