//! TLS server-certificate trust prompt stub (UI-independent).
//!
//! Mirrors C# [`ITlsTrustPromptService`](../../../../../../Services/Tunneling/ITlsTrustPromptService.cs):
//! providers surface a mid-connect prompt when TLS validation fails and the user may
//! legitimately override (factory/self-signed appliance certificates). Returns trust only
//! on explicit **AcceptOnce**; Reject / Cancel / missing UI fail-closed.
//!
//! **Wiring today:** Stormshield portal TLS consent loops are not yet ported — call
//! [`request_tls_trust`] from those paths when they land. Sidecar `establish` does **not**
//! invoke this prompt.
//!
//! Never log full certificate thumbprints in tracing — debug uses lengths and a short
//! fingerprint prefix only.

use std::collections::VecDeque;
use std::fmt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use tokio::sync::{mpsc, oneshot};

use crate::TunnelError;

/// Accept-action label implementations must put on the confirm button (C# parity).
pub const ACCEPT_BUTTON_LABEL: &str = "Trust and connect";

/// User answer to the TLS trust prompt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsTrustChoice {
    /// Trust this server and continue (persisted "Trust server certificate" in C#).
    AcceptOnce,
    /// Decline / dismiss — fail-closed at [`request_tls_trust`].
    Reject,
}

/// Prompt metadata shown to the user (certificate identity; no credentials).
#[derive(Clone, PartialEq, Eq)]
pub struct TlsTrustPromptRequest {
    pub title: String,
    pub message: String,
    /// SHA-1 thumbprint when the provider has it separately from `message`.
    pub fingerprint: Option<String>,
}

impl TlsTrustPromptRequest {
    pub fn new(
        title: impl Into<String>,
        message: impl Into<String>,
        fingerprint: Option<String>,
    ) -> Self {
        Self {
            title: title.into(),
            message: message.into(),
            fingerprint,
        }
    }
}

impl fmt::Debug for TlsTrustPromptRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsTrustPromptRequest")
            .field("title_len", &self.title.len())
            .field("message_len", &self.message.len())
            .field("fingerprint_prefix", &fingerprint_prefix(self.fingerprint.as_deref()))
            .finish()
    }
}

/// Outcome of a single TLS trust interaction (parity with C# `Task<bool>`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsTrustPromptResponse {
    AcceptOnce,
    Rejected,
}

/// Errors from the prompt transport (not user decline).
#[derive(Debug, thiserror::Error)]
pub enum TlsTrustPromptError {
    /// Caller cancellation / shutdown (C# `OperationCanceledException`).
    #[error("TLS trust prompt cancelled")]
    Cancelled,
    /// Channel mode: no UI listener / receiver dropped.
    #[error("TLS trust prompt channel closed")]
    ChannelClosed,
}

/// UI-thread-aware (eventually) TLS trust prompt — mirrors C# `ITlsTrustPromptService`.
#[async_trait]
pub trait TlsTrustPrompt: Send + Sync {
    async fn confirm_trust(
        &self,
        request: TlsTrustPromptRequest,
    ) -> Result<TlsTrustPromptResponse, TlsTrustPromptError>;
}

/// Provider hook: request TLS trust and return whether the user accepted.
///
/// Maps:
/// - AcceptOnce → `Ok(true)`
/// - Reject / dismiss → `TunnelError::Cancelled` (fail-closed)
/// - transport cancel / closed → `TunnelError::Cancelled`
///
/// Never logs full thumbprints — debug uses prefix + lengths only.
pub async fn request_tls_trust(
    prompt: &dyn TlsTrustPrompt,
    title: impl Into<String>,
    message: impl Into<String>,
    fingerprint: Option<String>,
) -> Result<bool, TunnelError> {
    let request = TlsTrustPromptRequest::new(title, message, fingerprint);
    tracing::debug!(
        title_len = request.title.len(),
        message_len = request.message.len(),
        fingerprint_prefix = ?fingerprint_prefix(request.fingerprint.as_deref()),
        "requesting TLS trust prompt"
    );

    let response = prompt.confirm_trust(request).await.map_err(|e| match e {
        TlsTrustPromptError::Cancelled | TlsTrustPromptError::ChannelClosed => TunnelError::Cancelled,
    })?;

    match response {
        TlsTrustPromptResponse::AcceptOnce => Ok(true),
        TlsTrustPromptResponse::Rejected => Err(TunnelError::Cancelled),
    }
}

/// Always rejects (`Rejected`). Fail-closed default until UI or tests attach.
#[derive(Debug, Default, Clone, Copy)]
pub struct NullTlsTrustPrompt;

#[async_trait]
impl TlsTrustPrompt for NullTlsTrustPrompt {
    async fn confirm_trust(
        &self,
        _request: TlsTrustPromptRequest,
    ) -> Result<TlsTrustPromptResponse, TlsTrustPromptError> {
        Ok(TlsTrustPromptResponse::Rejected)
    }
}

/// Scripted / in-memory TLS trust prompt for unit tests (parity with C# `ScriptedTlsTrustPrompt`).
///
/// Each [`confirm_trust`](TlsTrustPrompt::confirm_trust) dequeues the next queued choice.
/// Queue empty → Reject (fail-closed).
#[derive(Default)]
pub struct MemoryTlsTrustPrompt {
    script: Mutex<VecDeque<TlsTrustChoice>>,
    requests: Mutex<Vec<TlsTrustPromptRequest>>,
    prompt_count: AtomicUsize,
}

impl fmt::Debug for MemoryTlsTrustPrompt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let script = self.script.lock().unwrap_or_else(|p| p.into_inner());
        let requests = self.requests.lock().unwrap_or_else(|p| p.into_inner());
        f.debug_struct("MemoryTlsTrustPrompt")
            .field("script", &*script)
            .field("requests", &requests)
            .field("prompt_count", &self.prompt_count.load(Ordering::SeqCst))
            .finish()
    }
}

impl MemoryTlsTrustPrompt {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_choices(choices: impl IntoIterator<Item = TlsTrustChoice>) -> Self {
        let prompt = Self::new();
        for choice in choices {
            prompt.push(choice);
        }
        prompt
    }

    pub fn from_accepts(accepts: impl IntoIterator<Item = bool>) -> Self {
        Self::from_choices(accepts.into_iter().map(|accept| {
            if accept {
                TlsTrustChoice::AcceptOnce
            } else {
                TlsTrustChoice::Reject
            }
        }))
    }

    pub fn push(&self, choice: TlsTrustChoice) {
        self.script
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push_back(choice);
    }

    pub fn prompt_count(&self) -> usize {
        self.prompt_count.load(Ordering::SeqCst)
    }

    pub fn requests(&self) -> Vec<TlsTrustPromptRequest> {
        self.requests
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }
}

#[async_trait]
impl TlsTrustPrompt for MemoryTlsTrustPrompt {
    async fn confirm_trust(
        &self,
        request: TlsTrustPromptRequest,
    ) -> Result<TlsTrustPromptResponse, TlsTrustPromptError> {
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
            Some(TlsTrustChoice::AcceptOnce) => Ok(TlsTrustPromptResponse::AcceptOnce),
            Some(TlsTrustChoice::Reject) | None => Ok(TlsTrustPromptResponse::Rejected),
        }
    }
}

/// Alias used in tests — same type as [`MemoryTlsTrustPrompt`].
pub type FakeTlsTrustPrompt = MemoryTlsTrustPrompt;

#[derive(Debug)]
enum ChannelMode {
    AutoReject,
    Channel(mpsc::UnboundedSender<PendingTlsTrustPrompt>),
}

/// Pending prompt waiting for a UI (or test) decision.
pub struct PendingTlsTrustPrompt {
    pub request: TlsTrustPromptRequest,
    pub respond: oneshot::Sender<TlsTrustPromptResponse>,
}

impl fmt::Debug for PendingTlsTrustPrompt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PendingTlsTrustPrompt")
            .field("request", &self.request)
            .field("respond", &"<oneshot>")
            .finish()
    }
}

/// Channel-backed prompt for future UI wiring (independent of WinUI / GPUI).
#[derive(Debug)]
pub struct ChannelTlsTrustPrompt {
    mode: Mutex<ChannelMode>,
    prompt_count: AtomicUsize,
}

impl Default for ChannelTlsTrustPrompt {
    fn default() -> Self {
        Self::new()
    }
}

impl ChannelTlsTrustPrompt {
    pub fn new() -> Self {
        Self {
            mode: Mutex::new(ChannelMode::AutoReject),
            prompt_count: AtomicUsize::new(0),
        }
    }

    pub fn set_auto_reject(&self) {
        *self.mode.lock().unwrap_or_else(|p| p.into_inner()) = ChannelMode::AutoReject;
    }

    pub fn open_channel(&self) -> mpsc::UnboundedReceiver<PendingTlsTrustPrompt> {
        let (tx, rx) = mpsc::unbounded_channel();
        *self.mode.lock().unwrap_or_else(|p| p.into_inner()) = ChannelMode::Channel(tx);
        rx
    }

    pub fn prompt_count(&self) -> usize {
        self.prompt_count.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl TlsTrustPrompt for ChannelTlsTrustPrompt {
    async fn confirm_trust(
        &self,
        request: TlsTrustPromptRequest,
    ) -> Result<TlsTrustPromptResponse, TlsTrustPromptError> {
        self.prompt_count.fetch_add(1, Ordering::SeqCst);
        let respond_rx = {
            let mode = self.mode.lock().unwrap_or_else(|p| p.into_inner());
            match &*mode {
                ChannelMode::AutoReject => return Ok(TlsTrustPromptResponse::Rejected),
                ChannelMode::Channel(tx) => {
                    let (respond_tx, respond_rx) = oneshot::channel();
                    let pending = PendingTlsTrustPrompt {
                        request,
                        respond: respond_tx,
                    };
                    if tx.send(pending).is_err() {
                        return Err(TlsTrustPromptError::ChannelClosed);
                    }
                    respond_rx
                }
            }
        };
        respond_rx.await.map_err(|_| TlsTrustPromptError::ChannelClosed)
    }
}

/// Shared handle type for DI / future provider fields.
pub type SharedTlsTrustPrompt = Arc<dyn TlsTrustPrompt>;

fn fingerprint_prefix(fp: Option<&str>) -> Option<&str> {
    fp.filter(|s| !s.is_empty()).map(|s| {
        let take = s.len().min(8);
        &s[..take]
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_debug_uses_lengths_and_fingerprint_prefix() {
        let req = TlsTrustPromptRequest::new(
            "Unverified VPN server certificate — lab",
            "Thumbprint (SHA-1): ABCDEF0123456789",
            Some("ABCDEF0123456789".into()),
        );
        let dbg = format!("{req:?}");
        assert!(dbg.contains("title_len"));
        assert!(dbg.contains("message_len"));
        assert!(dbg.contains("fingerprint_prefix"));
        assert!(dbg.contains("ABCDEF01"));
        assert!(!dbg.contains("ABCDEF0123456789"), "{dbg}");
        assert!(!dbg.contains("lab"), "{dbg}");
    }

    #[test]
    fn memory_prompt_debug_omits_request_message_body() {
        let prompt = MemoryTlsTrustPrompt::new();
        prompt.push(TlsTrustChoice::AcceptOnce);
        let req = TlsTrustPromptRequest::new("title", "secret-ish message", None);
        let _ = prompt
            .requests
            .lock()
            .unwrap()
            .push(req);
        let dbg = format!("{prompt:?}");
        assert!(dbg.contains("AcceptOnce"));
        assert!(!dbg.contains("secret-ish"), "{dbg}");
    }

    #[tokio::test]
    async fn memory_prompt_accept_then_reject() {
        let prompt = MemoryTlsTrustPrompt::from_choices([
            TlsTrustChoice::AcceptOnce,
            TlsTrustChoice::Reject,
        ]);
        let r1 = prompt
            .confirm_trust(TlsTrustPromptRequest::new("t1", "m1", None))
            .await
            .unwrap();
        assert_eq!(r1, TlsTrustPromptResponse::AcceptOnce);
        let r2 = prompt
            .confirm_trust(TlsTrustPromptRequest::new("t2", "m2", None))
            .await
            .unwrap();
        assert_eq!(r2, TlsTrustPromptResponse::Rejected);
        let r3 = prompt
            .confirm_trust(TlsTrustPromptRequest::new("t3", "m3", None))
            .await
            .unwrap();
        assert_eq!(r3, TlsTrustPromptResponse::Rejected);
        assert_eq!(prompt.prompt_count(), 3);
    }

    #[tokio::test]
    async fn request_tls_trust_accept_returns_true() {
        let prompt = FakeTlsTrustPrompt::from_accepts([true]);
        let fp = Some("AA11BB22CC33DD44".into());
        let trusted = request_tls_trust(
            &prompt,
            "Unverified VPN server certificate — corp",
            "Certificate details…",
            fp,
        )
        .await
        .unwrap();
        assert!(trusted);
        assert_eq!(prompt.prompt_count(), 1);
        let req = &prompt.requests()[0];
        assert!(req.title.contains("corp"));
        assert_eq!(
            fingerprint_prefix(req.fingerprint.as_deref()),
            Some("AA11BB22")
        );
    }

    #[tokio::test]
    async fn request_tls_trust_reject_fail_closed() {
        let prompt = MemoryTlsTrustPrompt::from_accepts([false]);
        let err = request_tls_trust(&prompt, "t", "m", None).await.unwrap_err();
        assert!(matches!(err, TunnelError::Cancelled));
    }

    #[tokio::test]
    async fn null_prompt_always_rejects() {
        let direct = NullTlsTrustPrompt
            .confirm_trust(TlsTrustPromptRequest::new("t", "m", None))
            .await
            .unwrap();
        assert_eq!(direct, TlsTrustPromptResponse::Rejected);
        let err = request_tls_trust(&NullTlsTrustPrompt, "t", "m", None)
            .await
            .unwrap_err();
        assert!(matches!(err, TunnelError::Cancelled));
    }

    #[tokio::test]
    async fn channel_prompt_accept_and_reject() {
        let prompt = Arc::new(ChannelTlsTrustPrompt::new());
        let mut rx = prompt.open_channel();

        let accept = tokio::spawn({
            let prompt = Arc::clone(&prompt);
            async move { request_tls_trust(prompt.as_ref(), "Stormshield", "msg", None).await }
        });
        let pending = rx.recv().await.expect("pending");
        assert_eq!(pending.request.title, "Stormshield");
        pending
            .respond
            .send(TlsTrustPromptResponse::AcceptOnce)
            .unwrap();
        assert!(accept.await.unwrap().unwrap());

        let reject = tokio::spawn({
            let prompt = Arc::clone(&prompt);
            async move { request_tls_trust(prompt.as_ref(), "t", "m", None).await }
        });
        let pending = rx.recv().await.expect("pending reject");
        pending
            .respond
            .send(TlsTrustPromptResponse::Rejected)
            .unwrap();
        assert!(matches!(
            reject.await.unwrap().unwrap_err(),
            TunnelError::Cancelled
        ));
    }

    #[tokio::test]
    async fn channel_auto_reject_before_open() {
        let prompt = ChannelTlsTrustPrompt::new();
        let err = request_tls_trust(&prompt, "t", "m", None).await.unwrap_err();
        assert!(matches!(err, TunnelError::Cancelled));
        assert_eq!(prompt.prompt_count(), 1);
    }

    #[tokio::test]
    async fn channel_closed_when_receiver_dropped() {
        let prompt = ChannelTlsTrustPrompt::new();
        let rx = prompt.open_channel();
        drop(rx);
        let err = prompt
            .confirm_trust(TlsTrustPromptRequest::new("t", "m", None))
            .await
            .unwrap_err();
        assert!(matches!(err, TlsTrustPromptError::ChannelClosed));
    }

    #[tokio::test]
    async fn channel_pending_drop_maps_to_cancelled() {
        let prompt = Arc::new(ChannelTlsTrustPrompt::new());
        let mut rx = prompt.open_channel();
        let task = tokio::spawn({
            let prompt = Arc::clone(&prompt);
            async move { request_tls_trust(prompt.as_ref(), "t", "m", None).await }
        });
        let pending = rx.recv().await.expect("pending");
        drop(pending);
        assert!(matches!(
            task.await.unwrap().unwrap_err(),
            TunnelError::Cancelled
        ));
    }

    #[tokio::test]
    async fn channel_set_auto_reject_fail_closed_again() {
        let prompt = ChannelTlsTrustPrompt::new();
        let rx = prompt.open_channel();
        drop(rx);
        prompt.set_auto_reject();
        let err = request_tls_trust(&prompt, "t", "m", None).await.unwrap_err();
        assert!(matches!(err, TunnelError::Cancelled));
    }

    #[test]
    fn accept_button_label_matches_csharp() {
        assert_eq!(ACCEPT_BUTTON_LABEL, "Trust and connect");
    }
}
