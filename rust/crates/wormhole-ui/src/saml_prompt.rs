//! Fortinet SAML prompt UI glue — no WebView2 / GPUI / OS-browser chrome.
//!
//! Wires the existing [`wormhole_tunnels::ChannelSamlAuthCallback`] (establish side)
//! to a request/response Fake on the UI side. `establish_fortinet` /
//! `authenticate_fortinet_saml` call [`SamlAuthCallback::complete`]; the host (or
//! [`FakeSamlPromptUi`]) drains [`PendingSamlPrompt`] and replies Submit (`auth_id` /
//! `SVPNCOOKIE`) / Cancel over the oneshot.
//!
//! Mirrors C# `FortinetSamlAuthService` **transport** shape without a live browser.
//! Fail-closed map:
//! - user Cancel / Fake `None` / exhausted script / pending or channel abandon →
//!   [`SamlAuthError::Cancelled`] / [`SamlAuthError::ChannelClosed`] (establish maps
//!   both to [`TunnelError::Cancelled`])
//! - Submitted empty / whitespace / wrong credential kind → [`SamlAuthError::InvalidResult`]
//!   (never echoes tokens; distinct from Cancelled)
//!
//! Never log `auth_id` / `SVPNCOOKIE` — [`FakeSamlPromptUi`] [`Debug`] redacts queued
//! script values.

use std::collections::VecDeque;
use std::fmt;
use std::sync::Arc;

use tokio::sync::mpsc;
use wormhole_tunnels::{
    ChannelSamlAuthCallback, PendingSamlPrompt, SamlAuthError, SamlAuthRequest, SamlAuthResult,
    SamlPromptResponse, SharedSamlAuthCallback,
};

/// Open a provider-facing [`ChannelSamlAuthCallback`] and the UI-facing pending receiver.
///
/// Until [`SamlPromptChannel::open`] (or [`ChannelSamlAuthCallback::open_channel`]) the
/// channel auto-cancels (fail closed), matching Null / no-UI behaviour.
pub struct SamlPromptChannel {
    callback: Arc<ChannelSamlAuthCallback>,
    pending_rx: mpsc::UnboundedReceiver<PendingSamlPrompt>,
}

impl SamlPromptChannel {
    /// Create a channel-backed SAML callback and arm the UI listener.
    pub fn open() -> Self {
        let callback = Arc::new(ChannelSamlAuthCallback::new());
        let pending_rx = callback.open_channel();
        Self {
            callback,
            pending_rx,
        }
    }

    /// Establish / authenticate handle (`&dyn SamlAuthCallback` / DI).
    pub fn shared(&self) -> SharedSamlAuthCallback {
        Arc::clone(&self.callback) as SharedSamlAuthCallback
    }

    /// Borrow the concrete channel callback (complete counts, set_auto_cancel, …).
    pub fn callback(&self) -> &ChannelSamlAuthCallback {
        &self.callback
    }

    /// UI-facing pending queue (one [`PendingSamlPrompt`] per `complete` call).
    pub fn pending_rx(&mut self) -> &mut mpsc::UnboundedReceiver<PendingSamlPrompt> {
        &mut self.pending_rx
    }

    /// Detach the shared callback while keeping the receiver.
    pub fn into_parts(
        self,
    ) -> (
        SharedSamlAuthCallback,
        mpsc::UnboundedReceiver<PendingSamlPrompt>,
    ) {
        (self.shared(), self.pending_rx)
    }
}

impl fmt::Debug for SamlPromptChannel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SamlPromptChannel")
            .field("callback", &self.callback)
            .field("pending_rx", &"<mpsc>")
            .finish()
    }
}

/// Submit an ephemeral `auth_id` (external-browser path).
///
/// Never log `id`.
pub fn submit_auth_id(pending: PendingSamlPrompt, id: impl Into<String>) -> bool {
    pending
        .respond
        .send(SamlPromptResponse::from_auth_id(id))
        .is_ok()
}

/// Submit an ephemeral `SVPNCOOKIE` (embedded path).
///
/// Never log `cookie`.
pub fn submit_svpn_cookie(pending: PendingSamlPrompt, cookie: impl Into<String>) -> bool {
    pending
        .respond
        .send(SamlPromptResponse::from_svpn_cookie(cookie))
        .is_ok()
}

/// Submit a full [`SamlAuthResult`] (caller picks the credential kind).
pub fn submit_saml_result(pending: PendingSamlPrompt, result: SamlAuthResult) -> bool {
    pending
        .respond
        .send(SamlPromptResponse::Submitted(result))
        .is_ok()
}

/// User dismiss / Cancel on a pending prompt (fail closed at `authenticate`).
pub fn cancel_pending_saml(pending: PendingSamlPrompt) -> bool {
    pending.respond.send(SamlPromptResponse::Cancelled).is_ok()
}

/// Scripted UI responder for [`ChannelSamlAuthCallback`] / [`SamlPromptChannel`] tests.
///
/// Each [`answer_next`](FakeSamlPromptUi::answer_next) dequeues one scripted outcome and
/// replies on the pending oneshot. Exhausted / empty script → Cancel (fail closed).
///
/// [`Debug`] redacts queued tokens (`[REDACTED]`).
#[derive(Default)]
pub struct FakeSamlPromptUi {
    script: VecDeque<Option<SamlAuthResult>>,
    answered: usize,
    last_request: Option<SamlAuthRequest>,
}

impl fmt::Debug for FakeSamlPromptUi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let redacted: Vec<Option<&'static str>> = self
            .script
            .iter()
            .map(|slot| match slot {
                Some(SamlAuthResult::AuthId(_)) => Some("AuthId([REDACTED])"),
                Some(SamlAuthResult::SvpnCookie(_)) => Some("SvpnCookie([REDACTED])"),
                None => None,
            })
            .collect();
        f.debug_struct("FakeSamlPromptUi")
            .field("script", &redacted)
            .field("answered", &self.answered)
            .field("last_request", &self.last_request)
            .finish()
    }
}

impl FakeSamlPromptUi {
    pub fn new() -> Self {
        Self::default()
    }

    /// Queue submit results and optional cancels (`None` = user dismiss).
    pub fn from_results(results: impl IntoIterator<Item = Option<SamlAuthResult>>) -> Self {
        let mut ui = Self::new();
        for result in results {
            ui.push(result);
        }
        ui
    }

    /// Queue an ephemeral `auth_id` submit.
    pub fn push_auth_id(&mut self, id: impl Into<String>) {
        self.push(Some(SamlAuthResult::from_auth_id(id)));
    }

    /// Queue an ephemeral `SVPNCOOKIE` submit.
    pub fn push_svpn_cookie(&mut self, cookie: impl Into<String>) {
        self.push(Some(SamlAuthResult::from_svpn_cookie(cookie)));
    }

    /// Queue a user cancel.
    pub fn push_cancel(&mut self) {
        self.push(None);
    }

    pub fn push(&mut self, result: Option<SamlAuthResult>) {
        self.script.push_back(result);
    }

    pub fn answered_count(&self) -> usize {
        self.answered
    }

    pub fn last_request(&self) -> Option<&SamlAuthRequest> {
        self.last_request.as_ref()
    }

    /// Wait for one pending prompt and answer from the script (or cancel if exhausted).
    ///
    /// Returns the request metadata (never includes secrets). Errors if the channel closed
    /// before a pending arrived.
    pub async fn answer_next(
        &mut self,
        rx: &mut mpsc::UnboundedReceiver<PendingSamlPrompt>,
    ) -> Result<SamlAuthRequest, SamlAuthError> {
        let pending = rx.recv().await.ok_or(SamlAuthError::ChannelClosed)?;
        let request = pending.request.clone();
        self.last_request = Some(request.clone());
        self.answered += 1;
        match self.script.pop_front() {
            Some(Some(result)) => {
                let _ = submit_saml_result(pending, result);
            }
            Some(None) | None => {
                let _ = cancel_pending_saml(pending);
            }
        }
        Ok(request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use wormhole_tunnels::{
        authenticate_fortinet_saml, establish_fortinet, FakeFortinetConfigLookup, FakeFortinetSecretLookup,
        FakeTunnelProvider, FortinetConfigRecord, SamlAuthFlow, TunnelError, TunnelKind,
        DEFAULT_SAML_REDIRECT_PORT,
    };
    use uuid::Uuid;

    fn sso_external_settings() -> Vec<u8> {
        br#"{"Host":"vpn.example.com","Port":443,"UseSingleSignOn":true,"UseExternalBrowser":true,"SamlRedirectPort":8020}"#
            .to_vec()
    }

    fn sso_embedded_settings() -> Vec<u8> {
        br#"{"Host":"vpn.example.com","Port":443,"UseSingleSignOn":true,"UseExternalBrowser":false}"#
            .to_vec()
    }

    /// Shared Fake Fortinet lookups + provider for establish-path UI tests.
    struct FortiFixture {
        id: Uuid,
        configs: Arc<FakeFortinetConfigLookup>,
        secrets: Arc<FakeFortinetSecretLookup>,
        provider: Arc<FakeTunnelProvider>,
    }

    fn forti_fixture(id: &str, name: &str, settings: Vec<u8>) -> FortiFixture {
        let id = Uuid::parse_str(id).unwrap();
        FortiFixture {
            id,
            configs: Arc::new(FakeFortinetConfigLookup::new().with_config(
                FortinetConfigRecord::new(id, TunnelKind::Fortinet, name),
            )),
            secrets: Arc::new(FakeFortinetSecretLookup::new().with_secret(id, settings)),
            provider: Arc::new(FakeTunnelProvider::new(TunnelKind::Fortinet)),
        }
    }

    #[tokio::test]
    async fn channel_submit_auth_id_via_fake_ui() {
        let mut channel = SamlPromptChannel::open();
        let mut ui = FakeSamlPromptUi::new();
        ui.push_auth_id("  ephemeral-ui-auth-id  ");

        let callback = channel.shared();
        let task = tokio::spawn(async move {
            authenticate_fortinet_saml(
                callback.as_ref(),
                SamlAuthRequest::new("lab-vpn", SamlAuthFlow::external_browser_default()),
            )
            .await
        });

        let req = ui.answer_next(channel.pending_rx()).await.unwrap();
        assert_eq!(req.config_name, "lab-vpn");
        assert_eq!(
            req.flow,
            SamlAuthFlow::ExternalBrowser {
                callback_port: DEFAULT_SAML_REDIRECT_PORT
            }
        );
        let result = task.await.unwrap().unwrap();
        match &result {
            SamlAuthResult::AuthId(id) => assert_eq!(id.as_str(), "  ephemeral-ui-auth-id  "),
            SamlAuthResult::SvpnCookie(_) => panic!("expected AuthId"),
        }
        assert!(!format!("{result:?}").contains("ephemeral-ui-auth-id"));
        assert!(!format!("{ui:?}").contains("ephemeral-ui-auth-id"));
        assert_eq!(ui.answered_count(), 1);
    }

    #[tokio::test]
    async fn channel_submit_svpn_cookie_via_fake_ui() {
        let mut channel = SamlPromptChannel::open();
        let mut ui = FakeSamlPromptUi::new();
        ui.push_svpn_cookie("SVPNCOOKIE-UI-SECRET");

        let callback = channel.shared();
        let task = tokio::spawn(async move {
            authenticate_fortinet_saml(
                callback.as_ref(),
                SamlAuthRequest::new("emb", SamlAuthFlow::embedded()),
            )
            .await
        });

        ui.answer_next(channel.pending_rx()).await.unwrap();
        let result = task.await.unwrap().unwrap();
        match &result {
            SamlAuthResult::SvpnCookie(c) => assert_eq!(c.as_str(), "SVPNCOOKIE-UI-SECRET"),
            SamlAuthResult::AuthId(_) => panic!("expected SvpnCookie"),
        }
        assert!(!format!("{result:?}").contains("SVPNCOOKIE-UI-SECRET"));
        assert!(!format!("{ui:?}").contains("SVPNCOOKIE-UI-SECRET"));
    }

    #[tokio::test]
    async fn channel_cancel_via_fake_ui_fail_closed() {
        let mut channel = SamlPromptChannel::open();
        let mut ui = FakeSamlPromptUi::new();
        ui.push_cancel();

        let callback = channel.shared();
        let task = tokio::spawn(async move {
            authenticate_fortinet_saml(
                callback.as_ref(),
                SamlAuthRequest::new("x", SamlAuthFlow::embedded()),
            )
            .await
        });

        ui.answer_next(channel.pending_rx()).await.unwrap();
        assert_eq!(task.await.unwrap().unwrap_err(), SamlAuthError::Cancelled);
    }

    #[tokio::test]
    async fn fake_ui_exhausted_script_cancels() {
        let mut channel = SamlPromptChannel::open();
        let mut ui = FakeSamlPromptUi::new(); // empty → cancel

        let callback = channel.shared();
        let task = tokio::spawn(async move {
            authenticate_fortinet_saml(
                callback.as_ref(),
                SamlAuthRequest::new("x", SamlAuthFlow::external_browser_default()),
            )
            .await
        });

        ui.answer_next(channel.pending_rx()).await.unwrap();
        assert_eq!(task.await.unwrap().unwrap_err(), SamlAuthError::Cancelled);
        assert_eq!(ui.answered_count(), 1);
    }

    #[tokio::test]
    async fn submit_and_cancel_helpers() {
        let mut channel = SamlPromptChannel::open();

        let callback = channel.shared();
        let submit = tokio::spawn({
            let callback = Arc::clone(&callback);
            async move {
                authenticate_fortinet_saml(
                    callback.as_ref(),
                    SamlAuthRequest::new("Cisco-no", SamlAuthFlow::external_browser(8020)),
                )
                .await
            }
        });
        let pending = channel.pending_rx().recv().await.unwrap();
        assert!(submit_auth_id(pending, "auth-from-helper"));
        match submit.await.unwrap().unwrap() {
            SamlAuthResult::AuthId(id) => assert_eq!(id.as_str(), "auth-from-helper"),
            SamlAuthResult::SvpnCookie(_) => panic!("expected AuthId"),
        }

        let cancel = tokio::spawn({
            let callback = Arc::clone(&callback);
            async move {
                authenticate_fortinet_saml(
                    callback.as_ref(),
                    SamlAuthRequest::new("t", SamlAuthFlow::embedded()),
                )
                .await
            }
        });
        let pending = channel.pending_rx().recv().await.unwrap();
        assert!(cancel_pending_saml(pending));
        assert_eq!(cancel.await.unwrap().unwrap_err(), SamlAuthError::Cancelled);
    }

    #[test]
    fn fake_ui_debug_redacts_queued_tokens() {
        let mut ui = FakeSamlPromptUi::new();
        ui.push_auth_id("secret-auth-999");
        ui.push_svpn_cookie("secret-cookie-888");
        ui.push_cancel();
        let dbg = format!("{ui:?}");
        assert!(!dbg.contains("secret-auth-999"), "{dbg}");
        assert!(!dbg.contains("secret-cookie-888"), "{dbg}");
        assert!(dbg.contains("[REDACTED]"), "{dbg}");
        assert!(dbg.contains("None"), "{dbg}");
    }

    #[tokio::test]
    async fn pending_drop_maps_to_channel_closed() {
        let mut channel = SamlPromptChannel::open();
        let callback = channel.shared();
        let task = tokio::spawn(async move {
            authenticate_fortinet_saml(
                callback.as_ref(),
                SamlAuthRequest::new("t", SamlAuthFlow::embedded()),
            )
            .await
        });
        let pending = channel.pending_rx().recv().await.unwrap();
        drop(pending);
        assert_eq!(
            task.await.unwrap().unwrap_err(),
            SamlAuthError::ChannelClosed
        );
    }

    #[tokio::test]
    async fn drop_pending_rx_maps_to_channel_closed() {
        let channel = SamlPromptChannel::open();
        let callback = channel.shared();
        drop(channel);
        let err = authenticate_fortinet_saml(
            callback.as_ref(),
            SamlAuthRequest::new("t", SamlAuthFlow::embedded()),
        )
        .await
        .unwrap_err();
        assert_eq!(err, SamlAuthError::ChannelClosed);
    }

    #[tokio::test]
    async fn establish_fortinet_via_channel_fake_ui() {
        let fx = forti_fixture(
            "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            "ui-sso",
            sso_external_settings(),
        );

        let mut channel = SamlPromptChannel::open();
        let mut ui = FakeSamlPromptUi::new();
        ui.push_auth_id("UI_CHANNEL_AUTH_ID_SECRET");

        let callback = channel.shared();
        let task = tokio::spawn({
            let configs = Arc::clone(&fx.configs);
            let secrets = Arc::clone(&fx.secrets);
            let provider = Arc::clone(&fx.provider);
            let id = fx.id;
            async move {
                establish_fortinet(
                    id,
                    configs.as_ref(),
                    secrets.as_ref(),
                    provider.as_ref(),
                    callback.as_ref(),
                )
                .await
            }
        });

        let req = ui.answer_next(channel.pending_rx()).await.unwrap();
        assert_eq!(req.config_name, "ui-sso");
        let instance = task.await.unwrap().expect("establish");
        assert_eq!(instance.state(), wormhole_tunnels::TunnelState::Up);
        assert_eq!(fx.provider.establish_count(), 1);
        assert!(!format!("{ui:?}").contains("UI_CHANNEL_AUTH_ID_SECRET"));
    }

    #[tokio::test]
    async fn establish_fortinet_cancel_via_fake_ui_fail_closed() {
        let fx = forti_fixture(
            "bbbbbbbb-cccc-dddd-eeee-ffffffffffff",
            "ui-cancel",
            sso_embedded_settings(),
        );

        let mut channel = SamlPromptChannel::open();
        let mut ui = FakeSamlPromptUi::new();
        ui.push_cancel();

        let callback = channel.shared();
        let task = tokio::spawn({
            let configs = Arc::clone(&fx.configs);
            let secrets = Arc::clone(&fx.secrets);
            let provider = Arc::clone(&fx.provider);
            let id = fx.id;
            async move {
                establish_fortinet(
                    id,
                    configs.as_ref(),
                    secrets.as_ref(),
                    provider.as_ref(),
                    callback.as_ref(),
                )
                .await
            }
        });

        ui.answer_next(channel.pending_rx()).await.unwrap();
        let err = match task.await.unwrap() {
            Ok(_) => panic!("expected cancel"),
            Err(e) => e,
        };
        assert!(matches!(err, TunnelError::Cancelled), "{err:?}");
        assert_eq!(fx.provider.establish_count(), 0);
    }

    #[tokio::test]
    async fn external_plus_realm_still_rejected_before_prompt() {
        let id = Uuid::parse_str("cccccccc-dddd-eeee-ffff-000000000000").unwrap();
        let configs = FakeFortinetConfigLookup::new().with_config(
            FortinetConfigRecord::new(id, TunnelKind::Fortinet, "realm-ui"),
        );
        let secrets = FakeFortinetSecretLookup::new().with_secret(
            id,
            br#"{"Host":"vpn.example.com","UseSingleSignOn":true,"UseExternalBrowser":true,"SamlRedirectPort":8020,"Realm":"corp"}"#,
        );
        let provider = FakeTunnelProvider::new(TunnelKind::Fortinet);
        let channel = SamlPromptChannel::open();
        // Scripted token must not be consumed — preflight rejects first.
        let mut ui = FakeSamlPromptUi::new();
        ui.push_auth_id("should-not-be-consumed");

        let err = match establish_fortinet(
            id,
            &configs,
            &secrets,
            &provider,
            channel.callback(),
        )
        .await
        {
            Ok(_) => panic!("expected realm reject"),
            Err(e) => e,
        };
        assert!(format!("{err}").contains("realm"), "{err}");
        assert_eq!(channel.callback().complete_count(), 0);
        assert_eq!(provider.establish_count(), 0);
        assert_eq!(ui.answered_count(), 0);
    }

    #[tokio::test]
    async fn into_parts_keeps_request_response() {
        let channel = SamlPromptChannel::open();
        let (shared, mut rx) = channel.into_parts();
        let mut ui = FakeSamlPromptUi::new();
        ui.push_svpn_cookie("cookie-via-parts");

        let task = tokio::spawn(async move {
            authenticate_fortinet_saml(
                shared.as_ref(),
                SamlAuthRequest::new("parts", SamlAuthFlow::embedded()),
            )
            .await
        });
        let req = ui.answer_next(&mut rx).await.unwrap();
        assert_eq!(req.config_name, "parts");
        match task.await.unwrap().unwrap() {
            SamlAuthResult::SvpnCookie(c) => assert_eq!(c.as_str(), "cookie-via-parts"),
            SamlAuthResult::AuthId(_) => panic!("expected SvpnCookie"),
        }
    }

    #[tokio::test]
    async fn whitespace_token_fails_without_echo() {
        let mut channel = SamlPromptChannel::open();
        let mut ui = FakeSamlPromptUi::new();
        ui.push_auth_id("   ");

        let callback = channel.shared();
        let task = tokio::spawn(async move {
            authenticate_fortinet_saml(
                callback.as_ref(),
                SamlAuthRequest::new("t", SamlAuthFlow::external_browser_default()),
            )
            .await
        });
        ui.answer_next(channel.pending_rx()).await.unwrap();
        let err = task.await.unwrap().unwrap_err();
        assert_eq!(err, SamlAuthError::InvalidResult);
        assert!(!format!("{err}").contains("   "));
    }

    #[tokio::test]
    async fn empty_string_submit_is_invalid_result_not_cancelled() {
        // Transport accepts Submitted("") so authenticate can reject as InvalidResult
        // (distinct from Cancelled / ChannelClosed).
        let mut channel = SamlPromptChannel::open();
        let mut ui = FakeSamlPromptUi::new();
        ui.push_auth_id("");

        let callback = channel.shared();
        let task = tokio::spawn(async move {
            authenticate_fortinet_saml(
                callback.as_ref(),
                SamlAuthRequest::new("t", SamlAuthFlow::external_browser_default()),
            )
            .await
        });
        ui.answer_next(channel.pending_rx()).await.unwrap();
        let err = task.await.unwrap().unwrap_err();
        assert_eq!(err, SamlAuthError::InvalidResult);
        assert_ne!(err, SamlAuthError::Cancelled);
        assert_ne!(err, SamlAuthError::ChannelClosed);
    }

    #[tokio::test]
    async fn fake_ui_multi_step_submit_then_cancel() {
        let mut channel = SamlPromptChannel::open();
        let mut ui = FakeSamlPromptUi::from_results([
            Some(SamlAuthResult::from_svpn_cookie("cookie-step-1")),
            None,
        ]);

        let callback = channel.shared();
        let first = tokio::spawn({
            let callback = Arc::clone(&callback);
            async move {
                authenticate_fortinet_saml(
                    callback.as_ref(),
                    SamlAuthRequest::new("a", SamlAuthFlow::embedded()),
                )
                .await
            }
        });
        ui.answer_next(channel.pending_rx()).await.unwrap();
        match first.await.unwrap().unwrap() {
            SamlAuthResult::SvpnCookie(c) => assert_eq!(c.as_str(), "cookie-step-1"),
            SamlAuthResult::AuthId(_) => panic!("expected SvpnCookie"),
        }

        let second = tokio::spawn({
            let callback = Arc::clone(&callback);
            async move {
                authenticate_fortinet_saml(
                    callback.as_ref(),
                    SamlAuthRequest::new("b", SamlAuthFlow::embedded()),
                )
                .await
            }
        });
        ui.answer_next(channel.pending_rx()).await.unwrap();
        assert_eq!(second.await.unwrap().unwrap_err(), SamlAuthError::Cancelled);
        assert_eq!(ui.answered_count(), 2);
        assert!(!format!("{ui:?}").contains("cookie-step-1"));
    }

    #[tokio::test]
    async fn submit_helpers_false_when_provider_abandoned() {
        let mut channel = SamlPromptChannel::open();
        let callback = channel.shared();
        let task = tokio::spawn(async move {
            authenticate_fortinet_saml(
                callback.as_ref(),
                SamlAuthRequest::new("t", SamlAuthFlow::embedded()),
            )
            .await
        });
        let pending = channel.pending_rx().recv().await.unwrap();
        task.abort();
        tokio::task::yield_now().await;
        assert!(!submit_svpn_cookie(pending, "too-late"));
    }

    #[tokio::test]
    async fn establish_pending_drop_maps_to_cancelled() {
        let fx = forti_fixture(
            "dddddddd-eeee-ffff-0000-111111111111",
            "ui-abandon",
            sso_embedded_settings(),
        );

        let mut channel = SamlPromptChannel::open();
        let callback = channel.shared();
        let task = tokio::spawn({
            let configs = Arc::clone(&fx.configs);
            let secrets = Arc::clone(&fx.secrets);
            let provider = Arc::clone(&fx.provider);
            let id = fx.id;
            async move {
                establish_fortinet(
                    id,
                    configs.as_ref(),
                    secrets.as_ref(),
                    provider.as_ref(),
                    callback.as_ref(),
                )
                .await
            }
        });

        let pending = channel.pending_rx().recv().await.unwrap();
        drop(pending);
        let err = match task.await.unwrap() {
            Ok(_) => panic!("expected cancel"),
            Err(e) => e,
        };
        assert!(matches!(err, TunnelError::Cancelled), "{err:?}");
        assert_eq!(fx.provider.establish_count(), 0);
    }

    #[tokio::test]
    async fn wrong_kind_via_fake_ui_fails_without_echo() {
        let mut channel = SamlPromptChannel::open();
        let mut ui = FakeSamlPromptUi::new();
        // External flow expects auth_id; cookie → InvalidResult.
        ui.push_svpn_cookie("WRONG_KIND_SVPNCOOKIE_SECRET");

        let callback = channel.shared();
        let task = tokio::spawn(async move {
            authenticate_fortinet_saml(
                callback.as_ref(),
                SamlAuthRequest::new("t", SamlAuthFlow::external_browser(8020)),
            )
            .await
        });
        ui.answer_next(channel.pending_rx()).await.unwrap();
        let err = task.await.unwrap().unwrap_err();
        assert_eq!(err, SamlAuthError::InvalidResult);
        assert!(!format!("{err}").contains("WRONG_KIND_SVPNCOOKIE_SECRET"));
        assert!(!format!("{ui:?}").contains("WRONG_KIND_SVPNCOOKIE_SECRET"));
    }

    #[tokio::test]
    async fn shared_plus_pending_rx_is_the_join_pattern() {
        // authenticate lives on SharedSamlAuthCallback — pending_rx needs &mut self, so
        // the channel does not expose &self async helpers that would conflict with answering.
        let mut channel = SamlPromptChannel::open();
        let mut ui = FakeSamlPromptUi::new();
        ui.push_auth_id("join-pattern-id");
        let callback = channel.shared();
        let task = tokio::spawn(async move {
            authenticate_fortinet_saml(
                callback.as_ref(),
                SamlAuthRequest::new("join", SamlAuthFlow::external_browser_default()),
            )
            .await
        });
        let req = ui.answer_next(channel.pending_rx()).await.unwrap();
        assert_eq!(req.config_name, "join");
        match task.await.unwrap().unwrap() {
            SamlAuthResult::AuthId(id) => assert_eq!(id.as_str(), "join-pattern-id"),
            SamlAuthResult::SvpnCookie(_) => panic!("expected AuthId"),
        }
    }
}
