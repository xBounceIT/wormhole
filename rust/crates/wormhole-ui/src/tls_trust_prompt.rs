//! Tunnel TLS trust prompt UI glue — no GPUI / ContentDialog chrome.
//!
//! Wires [`wormhole_tunnels::ChannelTlsTrustPrompt`] (provider side) to a
//! request/response Fake on the UI side. Tunnel establish calls
//! [`wormhole_tunnels::request_tls_trust`] / [`wormhole_tunnels::TlsTrustPrompt::confirm_trust`];
//! the host (or [`FakeTlsTrustPromptUi`]) drains [`PendingTlsTrustPrompt`] and replies
//! AcceptOnce / Reject over the oneshot.
//!
//! Mirrors C# `DialogTlsTrustPromptService` **transport** shape without WinUI.
//! Fail-closed map:
//! - Reject / Fake exhausted / pending or channel abandon → [`TunnelError::Cancelled`]
//! - AcceptOnce → `Ok(true)` at [`request_tls_trust`]
//!
//! Never log full thumbprints — [`FakeTlsTrustPromptUi`] [`Debug`] uses fingerprint
//! prefix + lengths only.

use std::collections::VecDeque;
use std::fmt;
use std::sync::Arc;

use tokio::sync::mpsc;
use wormhole_tunnels::{
    ChannelTlsTrustPrompt, PendingTlsTrustPrompt, SharedTlsTrustPrompt, TlsTrustChoice,
    TlsTrustPromptError, TlsTrustPromptRequest, TlsTrustPromptResponse,
};

/// Open a provider-facing [`ChannelTlsTrustPrompt`] and the UI-facing pending receiver.
pub struct TlsTrustPromptChannel {
    prompt: Arc<ChannelTlsTrustPrompt>,
    pending_rx: mpsc::UnboundedReceiver<PendingTlsTrustPrompt>,
}

impl TlsTrustPromptChannel {
    pub fn open() -> Self {
        let prompt = Arc::new(ChannelTlsTrustPrompt::new());
        let pending_rx = prompt.open_channel();
        Self { prompt, pending_rx }
    }

    pub fn shared(&self) -> SharedTlsTrustPrompt {
        Arc::clone(&self.prompt) as SharedTlsTrustPrompt
    }

    pub fn prompt(&self) -> &ChannelTlsTrustPrompt {
        &self.prompt
    }

    pub fn pending_rx(&mut self) -> &mut mpsc::UnboundedReceiver<PendingTlsTrustPrompt> {
        &mut self.pending_rx
    }

    pub fn into_parts(
        self,
    ) -> (
        SharedTlsTrustPrompt,
        mpsc::UnboundedReceiver<PendingTlsTrustPrompt>,
    ) {
        (self.shared(), self.pending_rx)
    }
}

impl fmt::Debug for TlsTrustPromptChannel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsTrustPromptChannel")
            .field("prompt", &self.prompt)
            .field("pending_rx", &"<mpsc>")
            .finish()
    }
}

/// User chose "Trust and connect" on a pending prompt.
pub fn accept_pending(pending: PendingTlsTrustPrompt) -> bool {
    pending
        .respond
        .send(TlsTrustPromptResponse::AcceptOnce)
        .is_ok()
}

/// User dismissed / Cancel on a pending prompt (fail closed at `request_tls_trust`).
pub fn reject_pending(pending: PendingTlsTrustPrompt) -> bool {
    pending
        .respond
        .send(TlsTrustPromptResponse::Rejected)
        .is_ok()
}

/// Scripted UI responder for [`ChannelTlsTrustPrompt`] / [`TlsTrustPromptChannel`] tests.
///
/// Each [`answer_next`](FakeTlsTrustPromptUi::answer_next) dequeues one scripted choice and
/// replies on the pending oneshot. Exhausted / empty script → Reject (fail closed).
#[derive(Default)]
pub struct FakeTlsTrustPromptUi {
    script: VecDeque<TlsTrustChoice>,
    answered: usize,
    last_request: Option<TlsTrustPromptRequest>,
}

impl fmt::Debug for FakeTlsTrustPromptUi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FakeTlsTrustPromptUi")
            .field("script", &self.script)
            .field("answered", &self.answered)
            .field("last_request", &self.last_request)
            .finish()
    }
}

impl FakeTlsTrustPromptUi {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_choices(choices: impl IntoIterator<Item = TlsTrustChoice>) -> Self {
        let mut ui = Self::new();
        for choice in choices {
            ui.push(choice);
        }
        ui
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

    pub fn push(&mut self, choice: TlsTrustChoice) {
        self.script.push_back(choice);
    }

    pub fn answered_count(&self) -> usize {
        self.answered
    }

    pub fn last_request(&self) -> Option<&TlsTrustPromptRequest> {
        self.last_request.as_ref()
    }

    /// Wait for one pending prompt and answer from the script (or reject if exhausted).
    pub async fn answer_next(
        &mut self,
        rx: &mut mpsc::UnboundedReceiver<PendingTlsTrustPrompt>,
    ) -> Result<TlsTrustPromptRequest, TlsTrustPromptError> {
        let pending = rx.recv().await.ok_or(TlsTrustPromptError::ChannelClosed)?;
        let request = pending.request.clone();
        self.last_request = Some(request.clone());
        self.answered += 1;
        match self.script.pop_front() {
            Some(TlsTrustChoice::AcceptOnce) => {
                let _ = accept_pending(pending);
            }
            Some(TlsTrustChoice::Reject) | None => {
                let _ = reject_pending(pending);
            }
        }
        Ok(request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use wormhole_tunnels::{request_tls_trust, TunnelError};

    #[tokio::test]
    async fn channel_accept_via_fake_ui() {
        let mut channel = TlsTrustPromptChannel::open();
        let mut ui = FakeTlsTrustPromptUi::from_accepts([true]);

        let prompt = channel.shared();
        let task = tokio::spawn(async move {
            request_tls_trust(
                prompt.as_ref(),
                "Unverified VPN server certificate — lab",
                "Certificate details",
                Some("AA11BB22CC33".into()),
            )
            .await
        });

        let req = ui.answer_next(channel.pending_rx()).await.unwrap();
        assert!(req.title.contains("lab"));
        assert!(task.await.unwrap().unwrap());
        assert_eq!(ui.answered_count(), 1);
        let dbg = format!("{ui:?}");
        assert!(!dbg.contains("AA11BB22CC33"), "{dbg}");
    }

    #[tokio::test]
    async fn channel_reject_via_fake_ui_fail_closed() {
        let mut channel = TlsTrustPromptChannel::open();
        let mut ui = FakeTlsTrustPromptUi::from_accepts([false]);

        let prompt = channel.shared();
        let task = tokio::spawn(async move {
            request_tls_trust(prompt.as_ref(), "t", "m", None).await
        });

        ui.answer_next(channel.pending_rx()).await.unwrap();
        assert!(matches!(
            task.await.unwrap().unwrap_err(),
            TunnelError::Cancelled
        ));
    }

    #[tokio::test]
    async fn fake_ui_exhausted_script_rejects() {
        let mut channel = TlsTrustPromptChannel::open();
        let mut ui = FakeTlsTrustPromptUi::new();

        let prompt = channel.shared();
        let task = tokio::spawn(async move {
            request_tls_trust(prompt.as_ref(), "t", "m", None).await
        });

        ui.answer_next(channel.pending_rx()).await.unwrap();
        assert!(matches!(
            task.await.unwrap().unwrap_err(),
            TunnelError::Cancelled
        ));
        assert_eq!(ui.answered_count(), 1);
    }

    #[tokio::test]
    async fn accept_and_reject_helpers() {
        let mut channel = TlsTrustPromptChannel::open();
        let prompt = channel.shared();

        let accept = tokio::spawn({
            let prompt = Arc::clone(&prompt);
            async move {
                request_tls_trust(prompt.as_ref(), "Stormshield TLS", "msg", None).await
            }
        });
        let pending = channel.pending_rx().recv().await.unwrap();
        assert_eq!(pending.request.title, "Stormshield TLS");
        assert!(accept_pending(pending));
        assert!(accept.await.unwrap().unwrap());

        let reject = tokio::spawn({
            let prompt = Arc::clone(&prompt);
            async move { request_tls_trust(prompt.as_ref(), "t", "m", None).await }
        });
        let pending = channel.pending_rx().recv().await.unwrap();
        assert!(reject_pending(pending));
        assert!(matches!(
            reject.await.unwrap().unwrap_err(),
            TunnelError::Cancelled
        ));
    }

    #[tokio::test]
    async fn pending_drop_maps_to_cancelled() {
        let mut channel = TlsTrustPromptChannel::open();
        let prompt = channel.shared();
        let task = tokio::spawn(async move {
            request_tls_trust(prompt.as_ref(), "t", "m", None).await
        });
        let pending = channel.pending_rx().recv().await.unwrap();
        drop(pending);
        assert!(matches!(
            task.await.unwrap().unwrap_err(),
            TunnelError::Cancelled
        ));
    }

    #[tokio::test]
    async fn into_parts_keeps_request_response() {
        let channel = TlsTrustPromptChannel::open();
        let (shared, mut rx) = channel.into_parts();
        let mut ui = FakeTlsTrustPromptUi::from_accepts([true]);

        let task = tokio::spawn(async move {
            request_tls_trust(
                shared.as_ref(),
                "Unverified VPN server certificate — corp",
                "details",
                None,
            )
            .await
        });
        let req = ui.answer_next(&mut rx).await.unwrap();
        assert!(req.title.contains("corp"));
        assert!(task.await.unwrap().unwrap());
    }

    #[tokio::test]
    async fn drop_pending_rx_maps_to_cancelled() {
        let channel = TlsTrustPromptChannel::open();
        let prompt = channel.shared();
        drop(channel);
        let err = request_tls_trust(prompt.as_ref(), "t", "m", None)
            .await
            .unwrap_err();
        assert!(matches!(err, TunnelError::Cancelled));
    }

    #[tokio::test]
    async fn accept_pending_false_when_provider_abandoned() {
        let mut channel = TlsTrustPromptChannel::open();
        let prompt = channel.shared();
        let task = tokio::spawn(async move {
            request_tls_trust(prompt.as_ref(), "t", "m", None).await
        });
        let pending = channel.pending_rx().recv().await.unwrap();
        task.abort();
        tokio::task::yield_now().await;
        assert!(!accept_pending(pending));
    }

    #[test]
    fn request_debug_in_last_request_uses_prefix_only() {
        let req = TlsTrustPromptRequest::new(
            "title",
            "long message body",
            Some("ABCDEF0123456789".into()),
        );
        let ui = FakeTlsTrustPromptUi {
            script: VecDeque::new(),
            answered: 0,
            last_request: Some(req),
        };
        let dbg = format!("{ui:?}");
        assert!(dbg.contains("ABCDEF01"));
        assert!(!dbg.contains("ABCDEF0123456789"), "{dbg}");
        assert!(!dbg.contains("long message"), "{dbg}");
    }
}
