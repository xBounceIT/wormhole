//! Map profile ignore-cert / [`wormhole_http::HttpCertPolicy`] → WebView2
//! certificate-error action.
//!
//! Pure policy adapter + thin leaf/target glue only. This module does **not**
//! subscribe `ICoreWebView2::ServerCertificateErrorDetected` or call into COM.
//!
//! C# parity (`Views/Sessions/WebBrowserView.xaml.cs`): when
//! `HttpConnectionTarget.IgnoreCertErrors` is true, the view sets
//! `CoreWebView2ServerCertificateErrorAction.AlwaysAllow` on each cert-error
//! event. That subscription still belongs on the production HTTP host path;
//! surface-lab / wry create today leave the default (validate) behavior.
//!
//! **Lab ≠ production:** gates 3–5 and [`super::ChildWebViewHost::create`] do
//! **not** apply AlwaysAllow (default validation remains). Callers must wire
//! the COM handler explicitly when hosting HTTPS sessions with
//! [`HttpCertPolicy::IgnoreErrors`] — and **only** then — on an isolated
//! user-data folder (see [`super::env`]). Never treat this adapter as an
//! automatic create-time insecure default.
//!
//! Entry points:
//! - [`http_ignore_cert_to_webview2_behavior`] — profile `HttpIgnoreCertErrors`
//!   + scheme (fail-closed unless HTTPS ∧ leaf true)
//! - [`target_cert_to_webview2_behavior`] — built [`HttpConnectionTarget`]
//! - [`cert_policy_to_webview2_behavior`] — resolved [`HttpCertPolicy`]

use wormhole_http::{
    resolve_cert_policy, HttpCertPolicy, HttpConnectionTarget, HttpScheme,
};

/// WebView2 `CoreWebView2ServerCertificateErrorAction` stand-in (no COM).
///
/// Mirrors the C# enum values the HTTP view would set on
/// `ServerCertificateErrorDetected` — kept as a pure Rust enum so unit tests
/// and call sites do not need the WebView2 Runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum WebView2CertErrorAction {
    /// Default WebView2 behavior — validate certificates (reject errors).
    ///
    /// Maps to not subscribing AlwaysAllow / leaving the default action.
    #[default]
    Default,
    /// Accept the certificate error for this navigation
    /// (`CoreWebView2ServerCertificateErrorAction.AlwaysAllow`).
    ///
    /// Must only be used with a dedicated WebView2 environment / user-data
    /// folder — AlwaysAllow decisions are cached for the environment lifetime.
    AlwaysAllow,
}

impl WebView2CertErrorAction {
    /// `true` when the host must subscribe AlwaysAllow (C# ignore-cert path).
    pub fn allows_errors(self) -> bool {
        matches!(self, Self::AlwaysAllow)
    }
}

/// Map resolved HTTP cert policy → WebView2 certificate-error action.
///
/// | [`HttpCertPolicy`] | [`WebView2CertErrorAction`] |
/// |---|---|
/// | [`Default`](HttpCertPolicy::Default) | [`Default`](WebView2CertErrorAction::Default) |
/// | [`IgnoreErrors`](HttpCertPolicy::IgnoreErrors) | [`AlwaysAllow`](WebView2CertErrorAction::AlwaysAllow) |
///
/// This is the only mapping contract between `wormhole-http` policy and the
/// future surface-win COM handler. It does **not** attach the handler.
pub fn cert_policy_to_webview2_behavior(policy: HttpCertPolicy) -> WebView2CertErrorAction {
    match policy {
        HttpCertPolicy::Default => WebView2CertErrorAction::Default,
        HttpCertPolicy::IgnoreErrors => WebView2CertErrorAction::AlwaysAllow,
    }
}

/// Thin glue: profile leaf `HttpIgnoreCertErrors` + scheme → WebView2 action.
///
/// Chains [`resolve_cert_policy`] → [`cert_policy_to_webview2_behavior`].
/// **Fail-closed:** [`AlwaysAllow`](WebView2CertErrorAction::AlwaysAllow) only
/// when scheme is HTTPS **and** the leaf flag is true; plain HTTP or leaf
/// `false` always yields [`Default`](WebView2CertErrorAction::Default)
/// (validate). Does **not** subscribe COM — production HTTP host still wires
/// `ServerCertificateErrorDetected` explicitly.
///
/// **Leaf-only input:** pass the connection profile's resolved
/// `HttpIgnoreCertErrors` bool (`node.http_ignore_cert_errors.unwrap_or(false)`).
/// Folder-level ignore-cert is **not** inherited in domain resolution — do not
/// walk parents and OR a folder `true` into this argument. Scheme is the typed
/// [`HttpScheme`] enum (not a free-form string); URI builders emit lowercase
/// `http`/`https` only.
///
/// C# parity: `BuildTargetAsync` scheme gate, then
/// `WebBrowserView.OnServerCertificateErrorDetected` → `AlwaysAllow` only when
/// the resolved target has `IgnoreCertErrors`.
pub fn http_ignore_cert_to_webview2_behavior(
    scheme: HttpScheme,
    http_ignore_cert_errors: bool,
) -> WebView2CertErrorAction {
    cert_policy_to_webview2_behavior(resolve_cert_policy(scheme, http_ignore_cert_errors))
}

/// Thin glue: resolved [`HttpConnectionTarget::cert_policy`] → WebView2 action.
///
/// **Fail-closed** when policy is [`HttpCertPolicy::Default`]. Trusts the
/// target's already-resolved policy (builders call [`resolve_cert_policy`]);
/// routing (direct / SOCKS / forwarder) must not change the AlwaysAllow
/// decision. Same COM caveat as [`http_ignore_cert_to_webview2_behavior`].
pub fn target_cert_to_webview2_behavior(target: &HttpConnectionTarget) -> WebView2CertErrorAction {
    cert_policy_to_webview2_behavior(target.cert_policy)
}

#[cfg(test)]
mod tests {
    use super::*;
    use wormhole_http::{build_direct_target, resolve_cert_policy};

    #[test]
    fn default_policy_maps_to_default_action() {
        assert_eq!(
            cert_policy_to_webview2_behavior(HttpCertPolicy::Default),
            WebView2CertErrorAction::Default
        );
        assert!(!WebView2CertErrorAction::Default.allows_errors());
    }

    #[test]
    fn ignore_errors_maps_to_always_allow() {
        assert_eq!(
            cert_policy_to_webview2_behavior(HttpCertPolicy::IgnoreErrors),
            WebView2CertErrorAction::AlwaysAllow
        );
        assert!(WebView2CertErrorAction::AlwaysAllow.allows_errors());
    }

    /// Security pin: AlwaysAllow is reachable **only** via `IgnoreErrors`.
    /// `Default` must never opt into the insecure COM action.
    #[test]
    fn always_allow_only_from_ignore_errors() {
        let from_default = cert_policy_to_webview2_behavior(HttpCertPolicy::Default);
        let from_ignore = cert_policy_to_webview2_behavior(HttpCertPolicy::IgnoreErrors);

        assert_eq!(from_default, WebView2CertErrorAction::Default);
        assert_ne!(from_default, WebView2CertErrorAction::AlwaysAllow);
        assert!(!from_default.allows_errors());

        assert_eq!(from_ignore, WebView2CertErrorAction::AlwaysAllow);
        assert!(from_ignore.allows_errors());

        // Enum default must stay secure (validate), matching HttpCertPolicy::default().
        assert_eq!(
            WebView2CertErrorAction::default(),
            WebView2CertErrorAction::Default
        );
        assert_eq!(HttpCertPolicy::default(), HttpCertPolicy::Default);
        assert_eq!(
            cert_policy_to_webview2_behavior(HttpCertPolicy::default()),
            WebView2CertErrorAction::Default
        );
    }

    #[test]
    fn mapping_is_exhaustive_and_stable() {
        let cases = [
            (HttpCertPolicy::Default, WebView2CertErrorAction::Default),
            (
                HttpCertPolicy::IgnoreErrors,
                WebView2CertErrorAction::AlwaysAllow,
            ),
        ];
        for (policy, expected) in cases {
            assert_eq!(cert_policy_to_webview2_behavior(policy), expected);
            assert_eq!(expected.allows_errors(), policy.ignores_errors());
        }
        // Only two policy variants exist today — keep in sync if HttpCertPolicy grows.
        assert_eq!(cases.len(), 2);
    }

    /// Fail-closed: leaf false / plain HTTP never yield AlwaysAllow.
    #[test]
    fn leaf_glue_fail_closed_unless_https_and_true() {
        let cases = [
            (HttpScheme::Http, false, WebView2CertErrorAction::Default),
            (HttpScheme::Http, true, WebView2CertErrorAction::Default),
            (HttpScheme::Https, false, WebView2CertErrorAction::Default),
            (HttpScheme::Https, true, WebView2CertErrorAction::AlwaysAllow),
        ];
        for (scheme, leaf, expected) in cases {
            let got = http_ignore_cert_to_webview2_behavior(scheme, leaf);
            assert_eq!(got, expected, "scheme={scheme:?} leaf={leaf}");
            assert_eq!(
                got,
                cert_policy_to_webview2_behavior(resolve_cert_policy(scheme, leaf)),
                "glue must equal resolve→adapter"
            );
            if !matches!(scheme, HttpScheme::Https) || !leaf {
                assert!(!got.allows_errors(), "fail-closed {scheme:?} leaf={leaf}");
                assert_ne!(got, WebView2CertErrorAction::AlwaysAllow);
            }
        }
    }

    #[test]
    fn target_glue_uses_resolved_cert_policy() {
        let strict = build_direct_target(HttpScheme::Https, "fw.local", 443, false).unwrap();
        assert_eq!(
            target_cert_to_webview2_behavior(&strict),
            WebView2CertErrorAction::Default
        );
        assert!(!target_cert_to_webview2_behavior(&strict).allows_errors());

        let ignore = build_direct_target(HttpScheme::Https, "fw.local", 443, true).unwrap();
        assert_eq!(
            target_cert_to_webview2_behavior(&ignore),
            WebView2CertErrorAction::AlwaysAllow
        );
        assert!(target_cert_to_webview2_behavior(&ignore).allows_errors());

        // Plain HTTP + leaf true still fail-closed through builders → target glue.
        let http_leaf = build_direct_target(HttpScheme::Http, "fw.local", 80, true).unwrap();
        assert_eq!(http_leaf.cert_policy, HttpCertPolicy::Default);
        assert_eq!(
            target_cert_to_webview2_behavior(&http_leaf),
            WebView2CertErrorAction::Default
        );
    }

    /// Attack: folder `HttpIgnoreCertErrors=true` must not imply AlwaysAllow.
    /// Callers pass the **leaf-resolved** profile bool (unset → false).
    #[test]
    fn leaf_glue_treats_unset_as_false_not_folder_inherit() {
        // Domain: `node.http_ignore_cert_errors.unwrap_or(false)` — folder true
        // with leaf unset resolves to false. Glue must honor that false.
        let resolved_leaf_after_no_inherit = false;
        assert_eq!(
            http_ignore_cert_to_webview2_behavior(
                HttpScheme::Https,
                resolved_leaf_after_no_inherit
            ),
            WebView2CertErrorAction::Default
        );
        assert!(!http_ignore_cert_to_webview2_behavior(
            HttpScheme::Https,
            resolved_leaf_after_no_inherit
        )
        .allows_errors());

        // Only an explicit leaf true on HTTPS opts in.
        assert_eq!(
            http_ignore_cert_to_webview2_behavior(HttpScheme::Https, true),
            WebView2CertErrorAction::AlwaysAllow
        );
    }

    /// Attack: scheme is typed `HttpScheme`, not a case-variant string.
    /// Navigate URIs always use lowercase `http`/`https` from `as_str()`.
    #[test]
    fn scheme_is_typed_enum_not_string_case() {
        assert_eq!(HttpScheme::Http.as_str(), "http");
        assert_eq!(HttpScheme::Https.as_str(), "https");
        assert_ne!(HttpScheme::Https.as_str(), "HTTPS");
        assert_ne!(HttpScheme::Http.as_str(), "HTTP");

        // Glue decisions key off the enum variant, not string casing.
        assert_eq!(
            http_ignore_cert_to_webview2_behavior(HttpScheme::Https, true),
            WebView2CertErrorAction::AlwaysAllow
        );
        assert_eq!(
            http_ignore_cert_to_webview2_behavior(HttpScheme::Http, true),
            WebView2CertErrorAction::Default
        );
    }

    /// Routing (SOCKS / forwarder) must not change AlwaysAllow vs validate.
    #[test]
    fn target_glue_routing_preserves_fail_closed_matrix() {
        use std::net::{Ipv4Addr, SocketAddr};
        use wormhole_http::{build_forwarder_target, build_socks_target, Socks5Proxy};

        let socks = Socks5Proxy::new(SocketAddr::from((Ipv4Addr::LOCALHOST, 1080)));
        let cases = [
            (HttpScheme::Http, false, WebView2CertErrorAction::Default),
            (HttpScheme::Http, true, WebView2CertErrorAction::Default),
            (HttpScheme::Https, false, WebView2CertErrorAction::Default),
            (HttpScheme::Https, true, WebView2CertErrorAction::AlwaysAllow),
        ];
        for (scheme, leaf, expected) in cases {
            let port = i32::from(scheme.default_port());
            let direct = build_direct_target(scheme, "fw.local", port, leaf).unwrap();
            let socks_t =
                build_socks_target(scheme, "fw.local", port, leaf, socks, None).unwrap();
            let fwd =
                build_forwarder_target(scheme, "fw.local", port, leaf, 51515, None).unwrap();
            for (label, target) in [
                ("direct", &direct),
                ("socks", &socks_t),
                ("forwarder", &fwd),
            ] {
                let got = target_cert_to_webview2_behavior(target);
                assert_eq!(
                    got, expected,
                    "{label} scheme={scheme:?} leaf={leaf}"
                );
                assert_eq!(
                    got.allows_errors(),
                    target.ignore_cert_errors(),
                    "{label} allows_errors ↔ ignore_cert_errors"
                );
            }
        }
    }
}
