use std::net::SocketAddr;

use uuid::Uuid;

use crate::uri::build_navigate_uri;
use crate::HttpError;

/// http vs https (maps `ProtocolType::Http` / `Https`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HttpScheme {
    Http,
    Https,
}

impl HttpScheme {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Https => "https",
        }
    }

    pub fn default_port(self) -> u16 {
        match self {
            Self::Http => 80,
            Self::Https => 443,
        }
    }
}

/// WebView2 certificate validation policy for a navigation target.
///
/// Mirrors C# `HttpConnectionTarget.IgnoreCertErrors` **after** scheme gating
/// (`profile.Protocol == Https && profile.HttpIgnoreCertErrors`):
/// - [`Default`](Self::Default) — validate certificates normally
///   (`IgnoreCertErrors == false`; plain HTTP always lands here)
/// - [`IgnoreErrors`](Self::IgnoreErrors) — resolved "accept cert errors" for
///   HTTPS appliances / loopback-forwarder HTTPS where the cert name will not match
///
/// Leaf `HttpIgnoreCertErrors` is profile storage; this enum is the **resolved**
/// per-target policy. Use [`resolve_cert_policy`] for leaf flag → policy (the only
/// public scheme-gated path).
///
/// `ServerCertificateErrorDetected → AlwaysAllow` is **not** applied here.
/// `wormhole-surface-win` (`webview`) provides
/// `cert_policy_to_webview2_behavior` / `http_ignore_cert_to_webview2_behavior`
/// as pure mapping stubs (leaf/`HttpIgnoreCertErrors` → AlwaysAllow only when
/// HTTPS ∧ flag); the COM subscription remains a production HTTP-host concern
/// (surface-lab leaves default validation).
///
/// Targets carry no credentials — [`Debug`] never includes passwords/tokens
/// (fields are URI / proxy / policy / route only).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum HttpCertPolicy {
    /// Validate certificates (C# `IgnoreCertErrors = false`).
    #[default]
    Default,
    /// Accept certificate errors for this navigation (C# `IgnoreCertErrors = true`).
    IgnoreErrors,
}

impl HttpCertPolicy {
    /// `true` when policy is [`IgnoreErrors`](Self::IgnoreErrors)
    /// (C# `IgnoreCertErrors`; host AlwaysAllow is not applied here).
    pub fn ignores_errors(self) -> bool {
        matches!(self, Self::IgnoreErrors)
    }
}

/// Loopback SOCKS5 endpoint for WebView2 `--proxy-server=socks5://…`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Socks5Proxy {
    pub addr: SocketAddr,
}

impl Socks5Proxy {
    pub fn new(addr: SocketAddr) -> Self {
        Self { addr }
    }

    pub fn loopback(port: u16) -> Result<Self, HttpError> {
        if port == 0 {
            return Err(HttpError::InvalidPort(0));
        }
        Ok(Self {
            addr: SocketAddr::from(([127, 0, 0, 1], port)),
        })
    }

    /// Chromium `--proxy-server` host:port form (`127.0.0.1:1080`).
    pub fn proxy_server_endpoint(self) -> String {
        self.addr.to_string()
    }
}

/// How the tunnel routes this web session (informational for diagnostics).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelRouteHint {
    /// No tunnel — direct navigation.
    Direct,
    /// Tunnel exposes SOCKS5; navigate real hostname.
    Socks5,
    /// Tunnel has no SOCKS — navigate loopback forwarder.
    LocalForwarder,
}

/// Immutable description of where/how a web session should navigate.
///
/// Mirrors C# `HttpConnectionTarget`:
/// - `socks5_proxy` non-null ⇒ WebView2 must use SOCKS (`--proxy-server=socks5://…`)
/// - `cert_policy` ⇒ resolved HTTPS ignore-cert (plain HTTP always [`HttpCertPolicy::Default`])
/// - `original_uri` non-null ⇒ `navigate_uri` is a loopback forwarder for the real origin
/// - `tunnel_config_id` ⇒ stable routing identity for persistent browser profiles
///
/// **Ignore-cert isolation:** `cert_policy` is per-target only. When a future WebView2
/// host wires AlwaysAllow, callers must not share an environment that permanently
/// enables it across unrelated sessions — unique user-data dirs (surface-win) keep
/// cert policy isolated. This crate does **not** subscribe cert handlers.
///
/// **Secrets:** HTTP(S) targets are credential-less (no passwords/cookies/tokens).
/// Derived [`Debug`] prints only URI / SOCKS / policy / route fields — never
/// Credential Manager material or tunnel secrets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpConnectionTarget {
    pub navigate_uri: String,
    pub socks5_proxy: Option<Socks5Proxy>,
    pub cert_policy: HttpCertPolicy,
    pub original_uri: Option<String>,
    pub tunnel_config_id: Option<Uuid>,
    pub route: TunnelRouteHint,
}

impl HttpConnectionTarget {
    pub fn new(
        navigate_uri: String,
        socks5_proxy: Option<Socks5Proxy>,
        cert_policy: HttpCertPolicy,
        original_uri: Option<String>,
        tunnel_config_id: Option<Uuid>,
    ) -> Self {
        // SOCKS and loopback-forwarder are mutually exclusive routing modes.
        let original_uri = if socks5_proxy.is_some() {
            None
        } else {
            original_uri
        };
        let route = if socks5_proxy.is_some() {
            TunnelRouteHint::Socks5
        } else if original_uri.is_some() {
            TunnelRouteHint::LocalForwarder
        } else {
            TunnelRouteHint::Direct
        };
        Self {
            navigate_uri,
            socks5_proxy,
            cert_policy,
            original_uri,
            tunnel_config_id,
            route,
        }
    }

    /// C# `IgnoreCertErrors` bool parity (`cert_policy == IgnoreErrors`).
    pub fn ignore_cert_errors(&self) -> bool {
        self.cert_policy.ignores_errors()
    }
}

/// Resolve ignore-cert the C# way: HTTPS only, even if the leaf flag is set on HTTP.
pub fn effective_ignore_cert(scheme: HttpScheme, http_ignore_cert_errors: bool) -> bool {
    matches!(scheme, HttpScheme::Https) && http_ignore_cert_errors
}

/// Resolve [`HttpCertPolicy`] from scheme + leaf `HttpIgnoreCertErrors` (C# BuildTarget gating).
///
/// Only public leaf-flag → policy entry point: `IgnoreErrors` iff HTTPS ∧ leaf flag.
pub fn resolve_cert_policy(scheme: HttpScheme, http_ignore_cert_errors: bool) -> HttpCertPolicy {
    if effective_ignore_cert(scheme, http_ignore_cert_errors) {
        HttpCertPolicy::IgnoreErrors
    } else {
        HttpCertPolicy::Default
    }
}

fn validate_port(port: i32) -> Result<u16, HttpError> {
    u16::try_from(port)
        .map_err(|_| HttpError::InvalidPort(port))
        .and_then(|p| {
            if p == 0 {
                Err(HttpError::InvalidPort(port))
            } else {
                Ok(p)
            }
        })
}

/// Direct (no tunnel) target.
pub fn build_direct_target(
    scheme: HttpScheme,
    host: &str,
    port: i32,
    http_ignore_cert_errors: bool,
) -> Result<HttpConnectionTarget, HttpError> {
    let port = validate_port(port)?;
    let policy = resolve_cert_policy(scheme, http_ignore_cert_errors);
    let uri = build_navigate_uri(scheme.as_str(), host, port)?;
    Ok(HttpConnectionTarget::new(uri, None, policy, None, None))
}

/// Tunnel with SOCKS5: keep real host; carry proxy + optional tunnel config id.
pub fn build_socks_target(
    scheme: HttpScheme,
    host: &str,
    port: i32,
    http_ignore_cert_errors: bool,
    socks: Socks5Proxy,
    tunnel_config_id: Option<Uuid>,
) -> Result<HttpConnectionTarget, HttpError> {
    if socks.addr.port() == 0 {
        return Err(HttpError::InvalidPort(0));
    }
    let port = validate_port(port)?;
    let policy = resolve_cert_policy(scheme, http_ignore_cert_errors);
    let uri = build_navigate_uri(scheme.as_str(), host, port)?;
    Ok(HttpConnectionTarget::new(
        uri,
        Some(socks),
        policy,
        None,
        tunnel_config_id,
    ))
}

/// Tunnel without SOCKS: navigate loopback forwarder; keep original URI.
///
/// HTTPS over the forwarder almost always needs `HttpIgnoreCertErrors` because the
/// certificate name will not match `127.0.0.1`.
pub fn build_forwarder_target(
    scheme: HttpScheme,
    host: &str,
    port: i32,
    http_ignore_cert_errors: bool,
    local_forwarder_port: u16,
    tunnel_config_id: Option<Uuid>,
) -> Result<HttpConnectionTarget, HttpError> {
    if local_forwarder_port == 0 {
        return Err(HttpError::InvalidPort(0));
    }
    let port = validate_port(port)?;
    let policy = resolve_cert_policy(scheme, http_ignore_cert_errors);
    let original = build_navigate_uri(scheme.as_str(), host, port)?;
    let navigate = build_navigate_uri(scheme.as_str(), "127.0.0.1", local_forwarder_port)?;
    Ok(HttpConnectionTarget::new(
        navigate,
        None,
        policy,
        Some(original),
        tunnel_config_id,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddr};

    #[test]
    fn http_no_tunnel() {
        let t = build_direct_target(HttpScheme::Http, "fw.local", 80, false).unwrap();
        assert_eq!(t.navigate_uri, "http://fw.local:80/");
        assert!(t.socks5_proxy.is_none());
        assert_eq!(t.cert_policy, HttpCertPolicy::Default);
        assert!(!t.ignore_cert_errors());
        assert!(t.original_uri.is_none());
        assert_eq!(t.route, TunnelRouteHint::Direct);
    }

    #[test]
    fn https_ignore_cert_flows_as_policy() {
        let t = build_direct_target(HttpScheme::Https, "fw.local", 443, true).unwrap();
        assert_eq!(t.cert_policy, HttpCertPolicy::IgnoreErrors);
        assert!(t.ignore_cert_errors());
        assert_eq!(
            resolve_cert_policy(HttpScheme::Https, true),
            HttpCertPolicy::IgnoreErrors
        );
    }

    #[test]
    fn https_default_policy_when_leaf_false() {
        let t = build_direct_target(HttpScheme::Https, "fw.local", 443, false).unwrap();
        assert_eq!(t.cert_policy, HttpCertPolicy::Default);
        assert!(!t.ignore_cert_errors());
    }

    #[test]
    fn plain_http_never_ignores_cert() {
        let t = build_direct_target(HttpScheme::Http, "fw.local", 80, true).unwrap();
        assert_eq!(t.cert_policy, HttpCertPolicy::Default);
        assert!(!t.ignore_cert_errors());
        assert!(!effective_ignore_cert(HttpScheme::Http, true));
        assert!(effective_ignore_cert(HttpScheme::Https, true));
        assert!(!effective_ignore_cert(HttpScheme::Https, false));
        assert_eq!(
            resolve_cert_policy(HttpScheme::Http, true),
            HttpCertPolicy::Default
        );
        assert_eq!(
            resolve_cert_policy(HttpScheme::Https, false),
            HttpCertPolicy::Default
        );
    }

    #[test]
    fn socks_keeps_real_host_and_policy() {
        let id = Uuid::new_v4();
        let socks = Socks5Proxy::new(SocketAddr::from((Ipv4Addr::LOCALHOST, 1080)));
        let t = build_socks_target(HttpScheme::Https, "fw.local", 443, true, socks, Some(id))
            .unwrap();
        assert_eq!(t.navigate_uri, "https://fw.local:443/");
        assert_eq!(t.socks5_proxy, Some(socks));
        assert!(t.original_uri.is_none());
        assert_eq!(t.tunnel_config_id, Some(id));
        assert_eq!(t.route, TunnelRouteHint::Socks5);
        assert_eq!(t.cert_policy, HttpCertPolicy::IgnoreErrors);

        let t_default =
            build_socks_target(HttpScheme::Https, "fw.local", 443, false, socks, Some(id))
                .unwrap();
        assert_eq!(t_default.cert_policy, HttpCertPolicy::Default);

        let t_http =
            build_socks_target(HttpScheme::Http, "fw.local", 80, true, socks, None).unwrap();
        assert_eq!(t_http.cert_policy, HttpCertPolicy::Default);
    }

    #[test]
    fn forwarder_uses_loopback_and_policy() {
        let id = Uuid::new_v4();
        let t = build_forwarder_target(HttpScheme::Https, "fw.local", 443, true, 51515, Some(id))
            .unwrap();
        assert_eq!(t.navigate_uri, "https://127.0.0.1:51515/");
        assert_eq!(t.original_uri.as_deref(), Some("https://fw.local:443/"));
        assert!(t.socks5_proxy.is_none());
        assert_eq!(t.cert_policy, HttpCertPolicy::IgnoreErrors);
        assert!(t.ignore_cert_errors());
        assert_eq!(t.route, TunnelRouteHint::LocalForwarder);

        let t_off =
            build_forwarder_target(HttpScheme::Https, "fw.local", 443, false, 51515, Some(id))
                .unwrap();
        assert_eq!(t_off.cert_policy, HttpCertPolicy::Default);
        assert_eq!(t_off.navigate_uri, "https://127.0.0.1:51515/");

        let t_http =
            build_forwarder_target(HttpScheme::Http, "fw.local", 80, true, 51515, None).unwrap();
        assert_eq!(t_http.cert_policy, HttpCertPolicy::Default);
        assert_eq!(t_http.navigate_uri, "http://127.0.0.1:51515/");
    }

    #[test]
    fn ipv6_host() {
        let t = build_direct_target(HttpScheme::Https, "fd00::1", 443, false).unwrap();
        assert_eq!(t.navigate_uri, "https://[fd00::1]:443/");
        assert_eq!(t.cert_policy, HttpCertPolicy::Default);
    }

    #[test]
    fn rejects_invalid_ports() {
        assert_eq!(
            build_direct_target(HttpScheme::Http, "fw.local", 0, false),
            Err(HttpError::InvalidPort(0))
        );
        assert_eq!(
            build_direct_target(HttpScheme::Http, "fw.local", -1, false),
            Err(HttpError::InvalidPort(-1))
        );
        assert_eq!(
            build_direct_target(HttpScheme::Http, "fw.local", 70_000, false),
            Err(HttpError::InvalidPort(70_000))
        );
        assert_eq!(
            build_forwarder_target(HttpScheme::Https, "fw.local", 443, false, 0, None),
            Err(HttpError::InvalidPort(0))
        );
        assert_eq!(Socks5Proxy::loopback(0), Err(HttpError::InvalidPort(0)));
        let zero_socks = Socks5Proxy::new(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)));
        assert_eq!(
            build_socks_target(HttpScheme::Http, "fw.local", 80, false, zero_socks, None),
            Err(HttpError::InvalidPort(0))
        );
    }

    #[test]
    fn socks_and_original_uri_are_exclusive() {
        let socks = Socks5Proxy::new(SocketAddr::from((Ipv4Addr::LOCALHOST, 1080)));
        let t = HttpConnectionTarget::new(
            "https://fw.local:443/".into(),
            Some(socks),
            HttpCertPolicy::Default,
            Some("https://ignored/".into()),
            None,
        );
        assert!(t.original_uri.is_none());
        assert_eq!(t.route, TunnelRouteHint::Socks5);
        assert_eq!(t.cert_policy, HttpCertPolicy::Default);
    }

    #[test]
    fn rejects_malformed_host_in_builders() {
        assert_eq!(
            build_direct_target(HttpScheme::Https, "a/b", 443, false),
            Err(HttpError::InvalidHost)
        );
    }

    #[test]
    fn cert_policy_helpers() {
        assert!(!HttpCertPolicy::Default.ignores_errors());
        assert!(HttpCertPolicy::IgnoreErrors.ignores_errors());
        assert_eq!(HttpCertPolicy::default(), HttpCertPolicy::Default);
        assert_eq!(
            resolve_cert_policy(HttpScheme::Http, true),
            HttpCertPolicy::Default
        );
        assert_eq!(
            resolve_cert_policy(HttpScheme::Https, true),
            HttpCertPolicy::IgnoreErrors
        );
    }

    #[test]
    fn scheme_flag_matrix_all_builders() {
        let socks = Socks5Proxy::new(SocketAddr::from((Ipv4Addr::LOCALHOST, 1080)));
        let cases = [
            (HttpScheme::Http, false, HttpCertPolicy::Default),
            (HttpScheme::Http, true, HttpCertPolicy::Default),
            (HttpScheme::Https, false, HttpCertPolicy::Default),
            (HttpScheme::Https, true, HttpCertPolicy::IgnoreErrors),
        ];
        for (scheme, leaf, expected) in cases {
            assert_eq!(
                resolve_cert_policy(scheme, leaf),
                expected,
                "resolve {scheme:?} leaf={leaf}"
            );
            let host = "fw.local";
            let port = i32::from(scheme.default_port());
            let direct = build_direct_target(scheme, host, port, leaf).unwrap();
            assert_eq!(direct.cert_policy, expected, "direct {scheme:?} leaf={leaf}");
            let socks_t = build_socks_target(scheme, host, port, leaf, socks, None).unwrap();
            assert_eq!(socks_t.cert_policy, expected, "socks {scheme:?} leaf={leaf}");
            let fwd =
                build_forwarder_target(scheme, host, port, leaf, 51515, None).unwrap();
            assert_eq!(fwd.cert_policy, expected, "forwarder {scheme:?} leaf={leaf}");
        }
    }

    #[test]
    fn target_debug_has_no_secrets() {
        let socks = Socks5Proxy::new(SocketAddr::from((Ipv4Addr::LOCALHOST, 1080)));
        let id = Uuid::parse_str("01234567-89ab-cdef-0123-456789abcdef").unwrap();
        let t = build_socks_target(
            HttpScheme::Https,
            "fw.local",
            443,
            true,
            socks,
            Some(id),
        )
        .unwrap();
        let dbg = format!("{t:?}");
        assert!(dbg.contains("https://fw.local:443/"));
        assert!(dbg.contains("IgnoreErrors"));
        assert!(dbg.contains("cert_policy"));
        let lower = dbg.to_ascii_lowercase();
        for banned in [
            "password",
            "passwd",
            "secret",
            "token",
            "cookie",
            "credential",
            "authorization",
            "bearer",
        ] {
            assert!(
                !lower.contains(banned),
                "Debug must not look secret-bearing ({banned}): {dbg}"
            );
        }
        let policy_dbg = format!("{:?}", HttpCertPolicy::IgnoreErrors);
        assert!(!policy_dbg.to_ascii_lowercase().contains("password"));
        assert!(!policy_dbg.to_ascii_lowercase().contains("token"));
    }
}
