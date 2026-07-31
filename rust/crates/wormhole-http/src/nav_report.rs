//! HTTP/HTTPS navigation-result → session-status glue (Fake WebView surface).
//!
//! Thin Lab stub mirroring C# `HttpSessionViewModel.ReportNavigationSucceeded` /
//! `ReportNavigationFailed` and `WebBrowserView.OnNavigationCompleted`:
//!
//! | WebView outcome | Session status (only while [`HttpSessionNavStatus::Connecting`]) |
//! |---|---|
//! | [`NavigationOutcome::Succeeded`] | [`HttpSessionNavStatus::Connected`] |
//! | [`NavigationOutcome::Failed`] | [`HttpSessionNavStatus::Failed`] (+ message) |
//! | [`NavigationOutcome::Cancelled`] | **no change** (keep waiting; C# `OperationCanceled`) |
//!
//! Late reports (already Connected / Failed / Disconnected) are ignored.
//! Empty / whitespace-only navigate URIs **fail closed** before the Fake surface
//! records a navigation.
//!
//! [`HttpConnectionTarget::cert_policy`] is preserved on the session and Fake
//! surface (ignore-cert already resolved by builders / `resolve_cert_policy`).
//! This stub does **not** subscribe WebView2 `AlwaysAllow` — that stays in
//! `wormhole-surface-win` mapping helpers.
//!
//! **No GPUI / no live WebView2.** Unit tests drive [`FakeWebViewSurface`] only.
//! HTTP(S) is credential-less: [`Debug`] prints URI / policy / status / lengths
//! only (never passwords, cookies, or tunnel secrets). `Failed.message` must stay
//! a host-safe diagnostic.

use std::fmt;

use crate::target::{HttpCertPolicy, HttpConnectionTarget};
use crate::HttpError;

/// HTTP tab lifecycle status for the nav-report glue (C# `SessionStatus` subset).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HttpSessionNavStatus {
    Connecting,
    Connected,
    Failed,
    Disconnected,
}

/// Result reported by the (Fake) WebView after top-level navigation completes.
///
/// `Failed.message` is a host-safe diagnostic string (no secrets). Transport
/// failures mirror C# `transportFailure` (SOCKS dial collapsed to Unknown); this
/// stub records the flag but does **not** run the tunnel reachability probe.
#[derive(Clone, PartialEq, Eq)]
pub enum NavigationOutcome {
    Succeeded,
    Failed {
        message: String,
        transport_failure: bool,
    },
    /// C# `CoreWebView2WebErrorStatus.OperationCanceled` — keep waiting.
    Cancelled,
}

impl fmt::Debug for NavigationOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Succeeded => f.write_str("NavigationOutcome::Succeeded"),
            Self::Failed {
                message,
                transport_failure,
            } => f
                .debug_struct("NavigationOutcome::Failed")
                .field("message_len", &message.len())
                .field("transport_failure", transport_failure)
                .finish(),
            Self::Cancelled => f.write_str("NavigationOutcome::Cancelled"),
        }
    }
}

impl NavigationOutcome {
    pub fn failed(message: impl Into<String>) -> Self {
        Self::Failed {
            message: message.into(),
            transport_failure: false,
        }
    }

    pub fn transport_failed(message: impl Into<String>) -> Self {
        Self::Failed {
            message: message.into(),
            transport_failure: true,
        }
    }
}

/// In-memory WebView stand-in (no HWND / WebView2 / GPUI).
///
/// Records the last navigate URI + cert policy from the target. Policy is
/// storage-only here — COM AlwaysAllow is not applied.
#[derive(Clone, Default)]
pub struct FakeWebViewSurface {
    last_navigate_uri: Option<String>,
    cert_policy: HttpCertPolicy,
    navigate_count: usize,
    last_outcome: Option<NavigationOutcome>,
}

impl FakeWebViewSurface {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn last_navigate_uri(&self) -> Option<&str> {
        self.last_navigate_uri.as_deref()
    }

    pub fn cert_policy(&self) -> HttpCertPolicy {
        self.cert_policy
    }

    pub fn navigate_count(&self) -> usize {
        self.navigate_count
    }

    pub fn last_outcome(&self) -> Option<&NavigationOutcome> {
        self.last_outcome.as_ref()
    }

    /// Begin navigation to `target`. Empty / whitespace URI fails closed with
    /// **no** surface mutation (URI / count / policy unchanged).
    pub fn navigate(&mut self, target: &HttpConnectionTarget) -> Result<(), HttpError> {
        validate_navigate_uri(&target.navigate_uri)?;
        self.last_navigate_uri = Some(target.navigate_uri.clone());
        self.cert_policy = target.cert_policy;
        self.navigate_count = self.navigate_count.saturating_add(1);
        self.last_outcome = None;
        Ok(())
    }

    /// Record a completed navigation outcome (does not map session status).
    pub fn complete(&mut self, outcome: NavigationOutcome) {
        self.last_outcome = Some(outcome);
    }
}

impl fmt::Debug for FakeWebViewSurface {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FakeWebViewSurface")
            .field("last_navigate_uri", &self.last_navigate_uri)
            .field("cert_policy", &self.cert_policy)
            .field("navigate_count", &self.navigate_count)
            .field("last_outcome", &self.last_outcome)
            .finish()
    }
}

/// Session-side holder: target + status + optional error (C# VM report path).
///
/// Built from a resolved [`HttpConnectionTarget`]. Cert policy is preserved for
/// the lifetime of the stub session.
pub struct HttpNavSession {
    status: HttpSessionNavStatus,
    target: HttpConnectionTarget,
    error_message: Option<String>,
}

impl HttpNavSession {
    /// Start in [`HttpSessionNavStatus::Connecting`] with a non-empty navigate URI.
    pub fn begin(target: HttpConnectionTarget) -> Result<Self, HttpError> {
        validate_navigate_uri(&target.navigate_uri)?;
        Ok(Self {
            status: HttpSessionNavStatus::Connecting,
            target,
            error_message: None,
        })
    }

    pub fn status(&self) -> HttpSessionNavStatus {
        self.status
    }

    pub fn target(&self) -> &HttpConnectionTarget {
        &self.target
    }

    pub fn cert_policy(&self) -> HttpCertPolicy {
        self.target.cert_policy
    }

    pub fn error_message(&self) -> Option<&str> {
        self.error_message.as_deref()
    }

    pub fn is_connecting(&self) -> bool {
        self.status == HttpSessionNavStatus::Connecting
    }

    pub fn is_connected(&self) -> bool {
        self.status == HttpSessionNavStatus::Connected
    }

    pub fn is_failed(&self) -> bool {
        self.status == HttpSessionNavStatus::Failed
    }

    /// C# `ReportNavigationSucceeded` / `ReportNavigationFailed` (+ cancel no-op).
    ///
    /// Only applies while [`HttpSessionNavStatus::Connecting`].
    pub fn report_navigation(&mut self, outcome: NavigationOutcome) {
        apply_navigation_report(&mut self.status, &mut self.error_message, outcome);
    }

    /// Navigate the Fake surface then apply `outcome` to this session.
    ///
    /// [`Self::begin`] already rejects empty / whitespace URIs and the held
    /// target is immutable, so this path returns `Ok` for normal sessions.
    /// Empty fail-closed for ad-hoc targets is on [`FakeWebViewSurface::navigate`].
    pub fn navigate_and_report(
        &mut self,
        surface: &mut FakeWebViewSurface,
        outcome: NavigationOutcome,
    ) -> Result<(), HttpError> {
        surface.navigate(&self.target)?;
        surface.complete(outcome.clone());
        self.report_navigation(outcome);
        Ok(())
    }

    /// Mark disconnected (tab close / teardown). Ignores further nav reports.
    pub fn disconnect(&mut self) {
        self.status = HttpSessionNavStatus::Disconnected;
        self.error_message = None;
    }
}

impl fmt::Debug for HttpNavSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpNavSession")
            .field("status", &self.status)
            .field("navigate_uri", &self.target.navigate_uri)
            .field("cert_policy", &self.target.cert_policy)
            .field("route", &self.target.route)
            .field(
                "error_message_len",
                &self.error_message.as_ref().map(|m| m.len()),
            )
            .finish()
    }
}

/// Pure status transition (C# report methods). Cancel / non-Connecting → no-op.
pub fn apply_navigation_report(
    status: &mut HttpSessionNavStatus,
    error_message: &mut Option<String>,
    outcome: NavigationOutcome,
) {
    if *status != HttpSessionNavStatus::Connecting {
        return;
    }
    match outcome {
        NavigationOutcome::Succeeded => {
            *error_message = None;
            *status = HttpSessionNavStatus::Connected;
        }
        NavigationOutcome::Failed { message, .. } => {
            *error_message = Some(message);
            *status = HttpSessionNavStatus::Failed;
        }
        NavigationOutcome::Cancelled => {
            // Keep Connecting — wait for a real success/fail completion.
        }
    }
}

/// Fail closed on empty / whitespace-only navigate URI.
pub fn validate_navigate_uri(uri: &str) -> Result<(), HttpError> {
    if uri.trim().is_empty() {
        Err(HttpError::EmptyNavigateUri)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::target::{
        build_direct_target, build_forwarder_target, build_socks_target, HttpScheme, Socks5Proxy,
    };
    use std::net::{Ipv4Addr, SocketAddr};
    use uuid::Uuid;

    fn https_ignore_target() -> HttpConnectionTarget {
        build_direct_target(HttpScheme::Https, "fw.local", 443, true).unwrap()
    }

    fn http_target() -> HttpConnectionTarget {
        build_direct_target(HttpScheme::Http, "fw.local", 80, false).unwrap()
    }

    fn empty_uri_target(policy: HttpCertPolicy) -> HttpConnectionTarget {
        HttpConnectionTarget::new(String::new(), None, policy, None, None)
    }

    #[test]
    fn success_maps_connecting_to_connected() {
        let mut session = HttpNavSession::begin(https_ignore_target()).unwrap();
        assert!(session.is_connecting());
        assert_eq!(session.cert_policy(), HttpCertPolicy::IgnoreErrors);

        session.report_navigation(NavigationOutcome::Succeeded);
        assert!(session.is_connected());
        assert!(session.error_message().is_none());
        assert_eq!(session.cert_policy(), HttpCertPolicy::IgnoreErrors);
    }

    #[test]
    fn fail_maps_connecting_to_failed() {
        let mut session = HttpNavSession::begin(http_target()).unwrap();
        session.report_navigation(NavigationOutcome::failed("Navigation failed (Timeout)."));
        assert!(session.is_failed());
        assert_eq!(
            session.error_message(),
            Some("Navigation failed (Timeout).")
        );
        assert_eq!(session.cert_policy(), HttpCertPolicy::Default);
    }

    #[test]
    fn cancel_keeps_connecting() {
        let mut session = HttpNavSession::begin(http_target()).unwrap();
        session.report_navigation(NavigationOutcome::Cancelled);
        assert!(session.is_connecting());
        assert!(session.error_message().is_none());
    }

    /// C# `OperationCanceled` keeps waiting — a later real success/fail must apply.
    #[test]
    fn cancel_then_success_or_fail_still_applies() {
        let mut session = HttpNavSession::begin(https_ignore_target()).unwrap();
        session.report_navigation(NavigationOutcome::Cancelled);
        session.report_navigation(NavigationOutcome::Succeeded);
        assert!(session.is_connected());
        assert_eq!(session.cert_policy(), HttpCertPolicy::IgnoreErrors);

        let mut session = HttpNavSession::begin(https_ignore_target()).unwrap();
        session.report_navigation(NavigationOutcome::Cancelled);
        session.report_navigation(NavigationOutcome::failed("after cancel"));
        assert!(session.is_failed());
        assert_eq!(session.error_message(), Some("after cancel"));
        assert_eq!(session.cert_policy(), HttpCertPolicy::IgnoreErrors);
    }

    #[test]
    fn late_reports_ignored_when_not_connecting() {
        let mut session = HttpNavSession::begin(http_target()).unwrap();
        session.report_navigation(NavigationOutcome::Succeeded);
        session.report_navigation(NavigationOutcome::failed("late"));
        assert!(session.is_connected());
        assert!(session.error_message().is_none());

        // Late cancel must not demote Connected.
        session.report_navigation(NavigationOutcome::Cancelled);
        assert!(session.is_connected());

        session.disconnect();
        session.report_navigation(NavigationOutcome::Succeeded);
        session.report_navigation(NavigationOutcome::Cancelled);
        session.report_navigation(NavigationOutcome::failed("after disconnect"));
        assert_eq!(session.status(), HttpSessionNavStatus::Disconnected);
        assert!(session.error_message().is_none());
    }

    #[test]
    fn disconnect_while_connecting_blocks_later_success() {
        let mut session = HttpNavSession::begin(https_ignore_target()).unwrap();
        assert!(session.is_connecting());
        session.disconnect();
        session.report_navigation(NavigationOutcome::Succeeded);
        assert_eq!(session.status(), HttpSessionNavStatus::Disconnected);
        assert_eq!(session.cert_policy(), HttpCertPolicy::IgnoreErrors);
    }

    #[test]
    fn empty_uri_fail_closed_on_begin() {
        let err = HttpNavSession::begin(empty_uri_target(HttpCertPolicy::IgnoreErrors)).unwrap_err();
        assert_eq!(err, HttpError::EmptyNavigateUri);

        let whitespace = HttpConnectionTarget::new("   \t".into(), None, HttpCertPolicy::Default, None, None);
        assert_eq!(
            HttpNavSession::begin(whitespace).unwrap_err(),
            HttpError::EmptyNavigateUri
        );

        // Unicode White_Space (NBSP) — same trim fail-closed as ASCII blanks.
        let nbsp = HttpConnectionTarget::new("\u{00A0}".into(), None, HttpCertPolicy::Default, None, None);
        assert_eq!(
            HttpNavSession::begin(nbsp).unwrap_err(),
            HttpError::EmptyNavigateUri
        );
    }

    #[test]
    fn fake_surface_preserves_cert_policy_and_rejects_empty() {
        let mut surface = FakeWebViewSurface::new();
        let target = https_ignore_target();
        surface.navigate(&target).unwrap();
        assert_eq!(surface.last_navigate_uri(), Some("https://fw.local:443/"));
        assert_eq!(surface.cert_policy(), HttpCertPolicy::IgnoreErrors);
        assert_eq!(surface.navigate_count(), 1);

        let empty = empty_uri_target(HttpCertPolicy::IgnoreErrors);
        assert_eq!(surface.navigate(&empty).unwrap_err(), HttpError::EmptyNavigateUri);
        // Unchanged after fail-closed empty.
        assert_eq!(surface.last_navigate_uri(), Some("https://fw.local:443/"));
        assert_eq!(surface.cert_policy(), HttpCertPolicy::IgnoreErrors);
        assert_eq!(surface.navigate_count(), 1);

        // Whitespace-only is the other fail-closed entry (same validator as begin).
        let whitespace =
            HttpConnectionTarget::new(" \t\n".into(), None, HttpCertPolicy::Default, None, None);
        assert_eq!(
            surface.navigate(&whitespace).unwrap_err(),
            HttpError::EmptyNavigateUri
        );
        assert_eq!(surface.navigate_count(), 1);
        assert_eq!(surface.cert_policy(), HttpCertPolicy::IgnoreErrors);
    }

    #[test]
    fn failed_report_preserves_ignore_cert_policy() {
        let mut session = HttpNavSession::begin(https_ignore_target()).unwrap();
        session.report_navigation(NavigationOutcome::failed("cert rejected"));
        assert!(session.is_failed());
        assert_eq!(session.cert_policy(), HttpCertPolicy::IgnoreErrors);
        assert_eq!(session.target().cert_policy, HttpCertPolicy::IgnoreErrors);
    }

    #[test]
    fn navigate_and_report_success_via_fake() {
        let mut session = HttpNavSession::begin(https_ignore_target()).unwrap();
        let mut surface = FakeWebViewSurface::new();
        session
            .navigate_and_report(&mut surface, NavigationOutcome::Succeeded)
            .unwrap();
        assert!(session.is_connected());
        assert_eq!(surface.navigate_count(), 1);
        assert!(matches!(
            surface.last_outcome(),
            Some(NavigationOutcome::Succeeded)
        ));
        assert_eq!(surface.cert_policy(), session.cert_policy());
        assert_eq!(session.cert_policy(), HttpCertPolicy::IgnoreErrors);
    }

    #[test]
    fn navigate_and_report_transport_fail() {
        let mut session = HttpNavSession::begin(http_target()).unwrap();
        let mut surface = FakeWebViewSurface::new();
        session
            .navigate_and_report(
                &mut surface,
                NavigationOutcome::transport_failed("Navigation failed (Unknown)."),
            )
            .unwrap();
        assert!(session.is_failed());
        match surface.last_outcome() {
            Some(NavigationOutcome::Failed {
                transport_failure: true,
                message,
            }) => assert_eq!(message, "Navigation failed (Unknown)."),
            other => panic!("expected transport fail, got {other:?}"),
        }
    }

    #[test]
    fn cancel_via_fake_keeps_connecting_and_policy() {
        let mut session = HttpNavSession::begin(https_ignore_target()).unwrap();
        let mut surface = FakeWebViewSurface::new();
        session
            .navigate_and_report(&mut surface, NavigationOutcome::Cancelled)
            .unwrap();
        assert!(session.is_connecting());
        assert_eq!(session.cert_policy(), HttpCertPolicy::IgnoreErrors);
        assert_eq!(surface.cert_policy(), HttpCertPolicy::IgnoreErrors);
    }

    #[test]
    fn socks_and_forwarder_targets_preserve_policy_through_glue() {
        let socks = Socks5Proxy::new(SocketAddr::from((Ipv4Addr::LOCALHOST, 1080)));
        let id = Uuid::nil();
        let socks_t =
            build_socks_target(HttpScheme::Https, "fw.local", 443, true, socks, Some(id)).unwrap();
        let mut session = HttpNavSession::begin(socks_t).unwrap();
        assert_eq!(session.cert_policy(), HttpCertPolicy::IgnoreErrors);
        session.report_navigation(NavigationOutcome::Succeeded);
        assert_eq!(session.cert_policy(), HttpCertPolicy::IgnoreErrors);

        let fwd =
            build_forwarder_target(HttpScheme::Https, "fw.local", 443, true, 51515, Some(id))
                .unwrap();
        let mut session = HttpNavSession::begin(fwd).unwrap();
        let mut surface = FakeWebViewSurface::new();
        session
            .navigate_and_report(&mut surface, NavigationOutcome::Succeeded)
            .unwrap();
        assert_eq!(surface.last_navigate_uri(), Some("https://127.0.0.1:51515/"));
        assert_eq!(surface.cert_policy(), HttpCertPolicy::IgnoreErrors);
        assert_eq!(session.target().original_uri.as_deref(), Some("https://fw.local:443/"));
    }

    #[test]
    fn apply_navigation_report_pure() {
        let mut status = HttpSessionNavStatus::Connecting;
        let mut err = None;
        apply_navigation_report(&mut status, &mut err, NavigationOutcome::Cancelled);
        assert_eq!(status, HttpSessionNavStatus::Connecting);
        apply_navigation_report(&mut status, &mut err, NavigationOutcome::Succeeded);
        assert_eq!(status, HttpSessionNavStatus::Connected);
        apply_navigation_report(
            &mut status,
            &mut err,
            NavigationOutcome::failed("should ignore"),
        );
        assert_eq!(status, HttpSessionNavStatus::Connected);
        assert!(err.is_none());
    }

    #[test]
    fn debug_has_no_secrets() {
        let mut session = HttpNavSession::begin(https_ignore_target()).unwrap();
        session.report_navigation(NavigationOutcome::failed(
            "cert invalid — no password=secret token=abc cookie=x",
        ));
        let dbg = format!("{session:?}");
        assert!(dbg.contains("Failed"));
        assert!(dbg.contains("IgnoreErrors"));
        assert!(dbg.contains("error_message_len"));
        assert!(!dbg.contains("password=secret"));
        assert!(!dbg.contains("token=abc"));
        assert!(!dbg.contains("cookie=x"));

        let outcome = NavigationOutcome::failed("password=leak");
        let odbg = format!("{outcome:?}");
        assert!(odbg.contains("message_len"));
        assert!(!odbg.contains("password=leak"));

        let mut surface = FakeWebViewSurface::new();
        surface.navigate(&https_ignore_target()).unwrap();
        surface.complete(NavigationOutcome::failed("bearer=xyz password=nope"));
        let sdbg = format!("{surface:?}");
        assert!(sdbg.contains("FakeWebViewSurface"));
        assert!(sdbg.contains("IgnoreErrors"));
        assert!(sdbg.contains("message_len"));
        let lower = sdbg.to_ascii_lowercase();
        for banned in ["bearer=xyz", "password=nope", "authorization"] {
            assert!(
                !lower.contains(banned),
                "Fake surface Debug must not echo outcome body ({banned}): {sdbg}"
            );
        }
    }
}
