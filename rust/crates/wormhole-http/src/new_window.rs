//! HTTP/HTTPS WebView2 new-window / popup policy Fake glue.
//!
//! Pure port of `Helpers/WebViewNewWindowNavigation.cs` plus the Bitwarden
//! in-app popup URI builder from `WebBrowserView.BuildBitwardenPopupUri`.
//!
//! | Decision | Meaning (C# parity) |
//! |---|---|
//! | [`NewWindowPolicy::AllowInTab`] | `OnNewWindowRequested` → `Handled=true` + navigate existing tab |
//! | [`NewWindowPolicy::HostPopup`] | Bitwarden `chrome-extension://…` hosted in-app (never unmanaged Edge) |
//! | [`NewWindowPolicy::Block`] | Empty / `about:blank` / userinfo / unroutable cross-origin / bad inputs |
//!
//! Session new-window requests **never** open an unmanaged popup (would bypass
//! per-tab SOCKS / cert / tunnel). Bitwarden uses [`decide_bitwarden_popup`] /
//! [`build_bitwarden_popup_uri`] — a separate HostPopup path, not
//! `NewWindowRequested`.
//!
//! **No live WebView2 / GPUI.** Empty / whitespace URIs **fail closed** →
//! [`NewWindowPolicy::Block`]. [`Debug`] prints lengths / schemes / policy kind
//! only (never full URIs, extension ids, or query strings).

use std::fmt;

/// Outcome of a new-window / popup URI policy decision.
#[derive(Clone, PartialEq, Eq)]
pub enum NewWindowPolicy {
    /// Redirect into the existing session tab (C# `sender.Navigate`).
    AllowInTab { navigate_uri: String },
    /// Host an in-app popup WebView2 (Bitwarden extension popup only).
    HostPopup { popup_uri: String },
    /// Suppress — do not navigate and do not open an unmanaged window.
    Block,
}

impl fmt::Debug for NewWindowPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AllowInTab { navigate_uri } => f
                .debug_struct("NewWindowPolicy::AllowInTab")
                .field("navigate_uri_len", &navigate_uri.len())
                .field("scheme", &scheme_of(navigate_uri))
                .finish(),
            Self::HostPopup { popup_uri } => f
                .debug_struct("NewWindowPolicy::HostPopup")
                .field("popup_uri_len", &popup_uri.len())
                .field("scheme", &scheme_of(popup_uri))
                .finish(),
            Self::Block => f.write_str("NewWindowPolicy::Block"),
        }
    }
}

impl NewWindowPolicy {
    pub fn is_block(&self) -> bool {
        matches!(self, Self::Block)
    }

    pub fn is_allow_in_tab(&self) -> bool {
        matches!(self, Self::AllowInTab { .. })
    }

    pub fn is_host_popup(&self) -> bool {
        matches!(self, Self::HostPopup { .. })
    }

    pub fn navigate_uri(&self) -> Option<&str> {
        match self {
            Self::AllowInTab { navigate_uri } => Some(navigate_uri.as_str()),
            _ => None,
        }
    }

    pub fn popup_uri(&self) -> Option<&str> {
        match self {
            Self::HostPopup { popup_uri } => Some(popup_uri.as_str()),
            _ => None,
        }
    }
}

/// C# `WebViewNewWindowNavigation.GetInSessionNavigationUri`.
///
/// Returns `None` (caller blocks) for empty / whitespace / `about:blank` /
/// embedded userinfo / non-absolute (when bases present) / unroutable
/// cross-origin targets.
pub fn get_in_session_navigation_uri(
    raw_uri: Option<&str>,
    routed_base_uri: Option<&str>,
    original_base_uri: Option<&str>,
) -> Option<String> {
    let candidate = raw_uri?.trim();
    if candidate.is_empty() {
        return None;
    }
    if is_about_blank(candidate) {
        return None;
    }
    // Never allow credentialed authorities into the session tab (fail closed).
    if absolute_uri_has_userinfo(candidate) {
        return None;
    }

    let Some(routed) = routed_base_uri.filter(|s| !s.trim().is_empty()) else {
        return Some(candidate.to_string());
    };
    let Some(original) = original_base_uri.filter(|s| !s.trim().is_empty()) else {
        return Some(candidate.to_string());
    };

    let uri = parse_absolute_uri(candidate)?;
    let routed_origin = parse_absolute_uri(routed.trim())?;
    let original_origin = parse_absolute_uri(original.trim())?;

    if same_origin(&uri, &routed_origin) {
        return Some(candidate.to_string());
    }
    if !same_origin(&uri, &original_origin) {
        return None;
    }

    Some(rewrite_authority(&uri, &routed_origin))
}

/// Session-tab new-window policy (`OnNewWindowRequested` path).
///
/// Always [`AllowInTab`] or [`Block`] — never [`HostPopup`] (Bitwarden is
/// [`decide_bitwarden_popup`]). Empty URI fails closed → [`Block`].
pub fn decide_new_window_policy(
    raw_uri: Option<&str>,
    routed_base_uri: Option<&str>,
    original_base_uri: Option<&str>,
) -> NewWindowPolicy {
    match get_in_session_navigation_uri(raw_uri, routed_base_uri, original_base_uri) {
        Some(navigate_uri) => NewWindowPolicy::AllowInTab { navigate_uri },
        None => NewWindowPolicy::Block,
    }
}

/// C# `WebBrowserView.BuildBitwardenPopupUri`.
///
/// `chrome-extension://{id}/{popupPath}` with leading `/` stripped from the
/// popup path. Empty / whitespace id or path → `None` (fail closed).
pub fn build_bitwarden_popup_uri(extension_id: &str, popup_path: &str) -> Option<String> {
    let id = extension_id.trim();
    let path = popup_path.trim();
    if id.is_empty() || path.is_empty() {
        return None;
    }
    if !is_safe_extension_id(id) {
        return None;
    }
    let normalized = path.trim_start_matches('/');
    if normalized.is_empty() || normalized.contains("..") || normalized.contains('\\') {
        return None;
    }
    // Reject control / whitespace / scheme injection in the path segment tree.
    if normalized.chars().any(|c| c.is_control() || c.is_whitespace() || c == ':') {
        return None;
    }
    let uri = format!("chrome-extension://{id}/{normalized}");
    // Must parse as absolute chrome-extension (mirrors Uri.TryCreate Absolute).
    let parsed = parse_absolute_uri(&uri)?;
    if !parsed.scheme.eq_ignore_ascii_case("chrome-extension") {
        return None;
    }
    Some(uri)
}

/// Bitwarden extension popup policy — [`HostPopup`] or [`Block`] only.
///
/// Documented path: toolbar / activation builds the popup URI, then hosts it in
/// an in-app WebView2 dialog sharing the Bitwarden profile — **never** an
/// unmanaged Edge window and **never** a main-tab `AllowInTab` navigation.
pub fn decide_bitwarden_popup(extension_id: &str, popup_path: &str) -> NewWindowPolicy {
    match build_bitwarden_popup_uri(extension_id, popup_path) {
        Some(popup_uri) => NewWindowPolicy::HostPopup { popup_uri },
        None => NewWindowPolicy::Block,
    }
}

/// In-memory recorder for Fake unit tests (no HWND / WebView2).
#[derive(Clone, Default)]
pub struct FakeNewWindowSurface {
    decisions: Vec<NewWindowPolicy>,
}

impl FakeNewWindowSurface {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn decisions(&self) -> &[NewWindowPolicy] {
        &self.decisions
    }

    pub fn last(&self) -> Option<&NewWindowPolicy> {
        self.decisions.last()
    }

    pub fn decide_count(&self) -> usize {
        self.decisions.len()
    }

    /// Record a session new-window decision.
    pub fn on_new_window(
        &mut self,
        raw_uri: Option<&str>,
        routed_base_uri: Option<&str>,
        original_base_uri: Option<&str>,
    ) -> NewWindowPolicy {
        let policy = decide_new_window_policy(raw_uri, routed_base_uri, original_base_uri);
        self.decisions.push(policy.clone());
        policy
    }

    /// Record a Bitwarden HostPopup decision.
    pub fn on_bitwarden_popup(&mut self, extension_id: &str, popup_path: &str) -> NewWindowPolicy {
        let policy = decide_bitwarden_popup(extension_id, popup_path);
        self.decisions.push(policy.clone());
        policy
    }
}

impl fmt::Debug for FakeNewWindowSurface {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FakeNewWindowSurface")
            .field("decide_count", &self.decisions.len())
            .field("last", &self.decisions.last())
            .finish()
    }
}

// --- helpers ----------------------------------------------------------------

const ABOUT_BLANK: &str = "about:blank";

fn is_about_blank(uri: &str) -> bool {
    if uri.len() < ABOUT_BLANK.len() {
        return false;
    }
    if !uri[..ABOUT_BLANK.len()].eq_ignore_ascii_case(ABOUT_BLANK) {
        return false;
    }
    uri.len() == ABOUT_BLANK.len() || matches!(uri.as_bytes()[ABOUT_BLANK.len()], b'?' | b'#')
}

/// True when an absolute URI's authority embeds `userinfo@` (credentials).
fn absolute_uri_has_userinfo(raw: &str) -> bool {
    let Some(scheme_end) = raw.find("://") else {
        return false;
    };
    let after = &raw[scheme_end + 3..];
    let authority_end = after.find(['/', '?', '#']).unwrap_or(after.len());
    after[..authority_end].contains('@')
}

fn scheme_of(uri: &str) -> Option<&str> {
    let idx = uri.find("://")?;
    Some(&uri[..idx])
}

fn is_safe_extension_id(id: &str) -> bool {
    // Chrome extension ids are lowercase hex; accept conservative alphanumeric.
    !id.is_empty()
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

#[derive(Clone)]
struct ParsedUri {
    scheme: String,
    host: String,
    port: u16,
    /// Path + optional `?query` + optional `#fragment` (may be empty).
    path_query_fragment: String,
}

fn parse_absolute_uri(raw: &str) -> Option<ParsedUri> {
    let scheme_end = raw.find("://")?;
    if scheme_end == 0 {
        return None;
    }
    let scheme = raw[..scheme_end].to_ascii_lowercase();
    if scheme.is_empty() || !scheme.chars().all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '.' || c == '-')
    {
        return None;
    }
    let after_scheme = &raw[scheme_end + 3..];
    if after_scheme.is_empty() {
        return None;
    }

    let authority_end = after_scheme
        .find(['/', '?', '#'])
        .unwrap_or(after_scheme.len());
    let authority = &after_scheme[..authority_end];
    if authority.is_empty() {
        return None;
    }
    let path_query_fragment = after_scheme[authority_end..].to_string();

    let (host, port_opt) = split_authority_host_port(authority)?;
    if host.is_empty() {
        return None;
    }
    let port = port_opt.unwrap_or_else(|| default_port(&scheme));

    Some(ParsedUri {
        scheme,
        host: host.to_ascii_lowercase(),
        port,
        path_query_fragment,
    })
}

fn split_authority_host_port(authority: &str) -> Option<(&str, Option<u16>)> {
    // Reject userinfo — popup / new-window targets should not carry credentials.
    if authority.contains('@') {
        return None;
    }
    if authority.starts_with('[') {
        let close = authority.find(']')?;
        let host = &authority[..=close];
        let rest = &authority[close + 1..];
        if rest.is_empty() {
            return Some((host, None));
        }
        if !rest.starts_with(':') {
            return None;
        }
        let port: u16 = rest[1..].parse().ok()?;
        if port == 0 {
            return None;
        }
        return Some((host, Some(port)));
    }
    match authority.rsplit_once(':') {
        Some((host, port_str)) if !host.is_empty() && port_str.chars().all(|c| c.is_ascii_digit()) => {
            let port: u16 = port_str.parse().ok()?;
            if port == 0 {
                return None;
            }
            Some((host, Some(port)))
        }
        _ => Some((authority, None)),
    }
}

fn default_port(scheme: &str) -> u16 {
    match scheme {
        "https" => 443,
        "http" => 80,
        _ => 0,
    }
}

fn same_origin(uri: &ParsedUri, origin: &ParsedUri) -> bool {
    uri.scheme == origin.scheme && uri.host == origin.host && uri.port == origin.port
}

fn rewrite_authority(uri: &ParsedUri, routed: &ParsedUri) -> String {
    let path = if uri.path_query_fragment.is_empty() {
        "/".to_string()
    } else if uri.path_query_fragment.starts_with(['?', '#']) {
        // C# UriBuilder keeps an empty path as "/" before query/fragment.
        format!("/{}", uri.path_query_fragment)
    } else {
        uri.path_query_fragment.clone()
    };
    let authority = format_authority(&routed.host, routed.port, &routed.scheme);
    format!("{}://{}{}", routed.scheme, authority, path)
}

fn format_authority(host: &str, port: u16, scheme: &str) -> String {
    // Match C# UriBuilder: omit default http(s) ports in ToString.
    let default = default_port(scheme);
    if port == default && (scheme == "http" || scheme == "https") {
        host.to_string()
    } else {
        format!("{host}:{port}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_url_allows_in_tab() {
        for (raw, expected) in [
            ("https://fw.local/dashboard", "https://fw.local/dashboard"),
            ("http://fw.local/help", "http://fw.local/help"),
            ("  https://fw.local/dashboard  ", "https://fw.local/dashboard"),
        ] {
            let policy = decide_new_window_policy(Some(raw), None, None);
            assert_eq!(policy.navigate_uri(), Some(expected));
            assert!(policy.is_allow_in_tab());
        }
    }

    #[test]
    fn blank_targets_block() {
        for raw in [
            None,
            Some(""),
            Some(" "),
            Some("\t"),
            Some("\u{00a0}"), // NBSP — Unicode White_Space
            Some("about:blank"),
            Some("ABOUT:blank"),
            Some("about:blank#blocked"),
            Some("about:blank?popup"),
        ] {
            assert!(
                decide_new_window_policy(raw, None, None).is_block(),
                "expected Block for {raw:?}"
            );
            assert!(get_in_session_navigation_uri(raw, None, None).is_none());
        }
    }

    #[test]
    fn forwarder_rewrites_original_origin() {
        let policy = decide_new_window_policy(
            Some("https://fw.local:443/dashboard?tab=vpn#status"),
            Some("https://127.0.0.1:51515/"),
            Some("https://fw.local:443/"),
        );
        assert_eq!(
            policy.navigate_uri(),
            Some("https://127.0.0.1:51515/dashboard?tab=vpn#status")
        );
    }

    #[test]
    fn forwarder_allows_already_routed_popup_uri() {
        let policy = decide_new_window_policy(
            Some("https://127.0.0.1:51515/dashboard"),
            Some("https://127.0.0.1:51515/"),
            Some("https://fw.local:443/"),
        );
        assert_eq!(
            policy.navigate_uri(),
            Some("https://127.0.0.1:51515/dashboard")
        );
    }

    #[test]
    fn forwarder_blocks_unroutable_targets() {
        for raw in [
            "https://docs.example.com/",
            "https://fw.local:8443/dashboard",
            "/relative-popup",
            "not a uri",
        ] {
            assert!(
                decide_new_window_policy(
                    Some(raw),
                    Some("https://127.0.0.1:51515/"),
                    Some("https://fw.local:443/"),
                )
                .is_block(),
                "expected Block for {raw}"
            );
        }
    }

    #[test]
    fn either_base_missing_skips_origin_gate() {
        // C#: originalBaseUri is null || routedBaseUri is null → return candidate.
        let only_routed = decide_new_window_policy(
            Some("https://elsewhere.example/x"),
            Some("https://127.0.0.1:51515/"),
            None,
        );
        assert_eq!(
            only_routed.navigate_uri(),
            Some("https://elsewhere.example/x")
        );

        let only_original = decide_new_window_policy(
            Some("https://elsewhere.example/x"),
            None,
            Some("https://fw.local:443/"),
        );
        assert_eq!(
            only_original.navigate_uri(),
            Some("https://elsewhere.example/x")
        );
    }

    #[test]
    fn default_https_port_matches_explicit_443() {
        // https://fw.local/ → port 443; same origin as https://fw.local:443/
        let policy = decide_new_window_policy(
            Some("https://fw.local/popup"),
            Some("https://127.0.0.1:51515/"),
            Some("https://fw.local/"),
        );
        assert_eq!(
            policy.navigate_uri(),
            Some("https://127.0.0.1:51515/popup")
        );
    }

    #[test]
    fn default_http_port_matches_explicit_80() {
        let policy = decide_new_window_policy(
            Some("http://fw.local/popup"),
            Some("http://127.0.0.1:51515/"),
            Some("http://fw.local/"),
        );
        assert_eq!(
            policy.navigate_uri(),
            Some("http://127.0.0.1:51515/popup")
        );
    }

    #[test]
    fn bitwarden_popup_is_host_popup() {
        let policy = decide_bitwarden_popup("abcdefghijklmnopqrstuvwxyzabcdef", "popup/index.html");
        assert!(policy.is_host_popup());
        assert_eq!(
            policy.popup_uri(),
            Some("chrome-extension://abcdefghijklmnopqrstuvwxyzabcdef/popup/index.html")
        );
        // Leading slash stripped.
        let with_slash = build_bitwarden_popup_uri("abcdefghijklmnopqrstuvwxyzabcdef", "/popup/index.html");
        assert_eq!(
            with_slash.as_deref(),
            Some("chrome-extension://abcdefghijklmnopqrstuvwxyzabcdef/popup/index.html")
        );
    }

    #[test]
    fn bitwarden_popup_empty_fail_closed() {
        for (id, path) in [
            ("", "popup.html"),
            (" ", "popup.html"),
            ("\u{00a0}", "popup.html"),
            ("extid", ""),
            ("extid", " "),
            ("extid", "/"),
            ("bad id", "popup.html"),
            ("extid", "../popup.html"),
            ("extid", "pop up.html"),
            ("extid", "chrome-extension://evil"),
        ] {
            assert!(
                decide_bitwarden_popup(id, path).is_block(),
                "expected Block for id={id:?} path={path:?}"
            );
            assert!(build_bitwarden_popup_uri(id, path).is_none());
        }
    }

    #[test]
    fn session_new_window_never_returns_host_popup() {
        // Even a chrome-extension URI on the NewWindow path stays AllowInTab
        // (or Block with bases) — HostPopup is Bitwarden-only.
        let policy = decide_new_window_policy(
            Some("chrome-extension://abcdefghijklmnopqrstuvwxyzabcdef/popup/index.html"),
            None,
            None,
        );
        assert!(policy.is_allow_in_tab());
        assert!(!policy.is_host_popup());

        // With forwarder bases, extension origin is unroutable → Block (not HostPopup).
        let with_bases = decide_new_window_policy(
            Some("chrome-extension://abcdefghijklmnopqrstuvwxyzabcdef/popup/index.html"),
            Some("https://127.0.0.1:51515/"),
            Some("https://fw.local:443/"),
        );
        assert!(with_bases.is_block());
        assert!(!with_bases.is_host_popup());
    }

    #[test]
    fn userinfo_in_authority_fail_closed() {
        let with_bases = decide_new_window_policy(
            Some("https://user:pass@fw.local/dashboard"),
            Some("https://127.0.0.1:51515/"),
            Some("https://fw.local:443/"),
        );
        assert!(with_bases.is_block());

        // Also fail closed without bases — never AllowInTab credentialed URIs.
        let no_bases =
            decide_new_window_policy(Some("https://user:pass@fw.local/dashboard"), None, None);
        assert!(no_bases.is_block());
    }

    #[test]
    fn forwarder_rewrites_query_only_path() {
        let policy = decide_new_window_policy(
            Some("https://fw.local:443?tab=1"),
            Some("https://127.0.0.1:51515/"),
            Some("https://fw.local:443/"),
        );
        assert_eq!(
            policy.navigate_uri(),
            Some("https://127.0.0.1:51515/?tab=1")
        );
    }

    #[test]
    fn debug_redacts_uris_and_extension_ids() {
        let allow = decide_new_window_policy(Some("https://fw.local/secret-token=abc"), None, None);
        let dbg = format!("{allow:?}");
        assert!(dbg.contains("navigate_uri_len"));
        assert!(!dbg.contains("secret-token"));
        assert!(!dbg.contains("fw.local/secret"));

        let popup = decide_bitwarden_popup("abcdefghijklmnopqrstuvwxyzabcdef", "popup/index.html");
        let dbg = format!("{popup:?}");
        assert!(dbg.contains("popup_uri_len"));
        assert!(!dbg.contains("abcdefghijklmnopqrstuvwxyzabcdef"));
        assert!(!dbg.contains("chrome-extension://"));
    }

    #[test]
    fn fake_surface_records_decisions() {
        let mut fake = FakeNewWindowSurface::new();
        assert!(fake
            .on_new_window(Some("about:blank"), None, None)
            .is_block());
        assert!(fake
            .on_new_window(Some("https://fw.local/x"), None, None)
            .is_allow_in_tab());
        assert!(fake
            .on_bitwarden_popup("abcdefghijklmnopqrstuvwxyzabcdef", "popup.html")
            .is_host_popup());
        assert_eq!(fake.decide_count(), 3);
        assert!(fake.last().unwrap().is_host_popup());
        let surface_dbg = format!("{fake:?}");
        assert!(surface_dbg.contains("decide_count"));
        assert!(!surface_dbg.contains("abcdefghijklmnopqrstuvwxyzabcdef"));
    }

    #[test]
    fn ipv6_forwarder_rewrite() {
        let policy = decide_new_window_policy(
            Some("https://[2001:db8::1]:443/app"),
            Some("https://127.0.0.1:51515/"),
            Some("https://[2001:db8::1]:443/"),
        );
        assert_eq!(policy.navigate_uri(), Some("https://127.0.0.1:51515/app"));
    }
}
