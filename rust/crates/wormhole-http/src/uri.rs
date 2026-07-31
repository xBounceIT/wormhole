//! Build navigate URIs the way C# `UriBuilder` does (path `/`, bracket IPv6).

use crate::HttpError;

/// Produce `scheme://host:port/` (IPv6 host literals are bracketed).
pub fn build_navigate_uri(scheme: &str, host: &str, port: u16) -> Result<String, HttpError> {
    if scheme != "http" && scheme != "https" {
        return Err(HttpError::InvalidScheme);
    }
    let host = validate_host(host)?;
    if port == 0 {
        return Err(HttpError::InvalidPort(0));
    }
    let authority = format_authority(host, port);
    Ok(format!("{scheme}://{authority}/"))
}

/// Reject empty / whitespace / injection-prone host strings.
///
/// Returns the trimmed host on success.
pub fn validate_host(host: &str) -> Result<&str, HttpError> {
    let host = host.trim();
    if host.is_empty() {
        return Err(HttpError::EmptyHost);
    }
    if host.chars().any(|c| {
        c.is_whitespace()
            || c.is_control()
            || matches!(c, '/' | '\\' | '?' | '#' | '@' | '"' | '\'' | '<' | '>')
    }) {
        return Err(HttpError::InvalidHost);
    }
    // Reject scheme-like prefixes (`http:`, `https:`) that would produce nested URIs.
    // Bare IPv6 (possibly already bracketed) may contain ':'; hostnames must not
    // look like `http:evil` / `host:443` (port belongs in the port argument).
    if host.contains(':')
        && !(host.starts_with('[') && host.ends_with(']'))
        && !looks_like_ipv6(host)
    {
        return Err(HttpError::InvalidHost);
    }
    // Reject half-open brackets.
    if host.starts_with('[') ^ host.ends_with(']') {
        return Err(HttpError::InvalidHost);
    }
    if host.starts_with('[') && host.ends_with(']') {
        let inner = &host[1..host.len() - 1];
        if inner.is_empty() || !looks_like_ipv6(inner) {
            return Err(HttpError::InvalidHost);
        }
    }
    Ok(host)
}

fn looks_like_ipv6(host: &str) -> bool {
    // Minimal check: contains ':' and only hex / colon / dot (IPv4-mapped) chars.
    if !host.contains(':') {
        return false;
    }
    host.chars()
        .all(|c| c.is_ascii_hexdigit() || c == ':' || c == '.')
}

fn format_authority(host: &str, port: u16) -> String {
    if needs_brackets(host) {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

fn needs_brackets(host: &str) -> bool {
    // Bare IPv6 literal contains ':' and is not already bracketed.
    host.contains(':') && !(host.starts_with('[') && host.ends_with(']'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_and_name() {
        assert_eq!(
            build_navigate_uri("https", "fw.local", 443).unwrap(),
            "https://fw.local:443/"
        );
        assert_eq!(
            build_navigate_uri("https", "10.0.0.1", 8443).unwrap(),
            "https://10.0.0.1:8443/"
        );
    }

    #[test]
    fn ipv6_is_bracketed() {
        assert_eq!(
            build_navigate_uri("https", "fd00::1", 443).unwrap(),
            "https://[fd00::1]:443/"
        );
    }

    #[test]
    fn already_bracketed_ipv6() {
        assert_eq!(
            build_navigate_uri("http", "[fd00::1]", 80).unwrap(),
            "http://[fd00::1]:80/"
        );
    }

    #[test]
    fn rejects_empty_and_whitespace_hosts() {
        assert_eq!(build_navigate_uri("http", "", 80), Err(HttpError::EmptyHost));
        assert_eq!(
            build_navigate_uri("http", "   ", 80),
            Err(HttpError::EmptyHost)
        );
    }

    #[test]
    fn rejects_malformed_hosts() {
        assert_eq!(
            build_navigate_uri("https", "evil.com/path", 443),
            Err(HttpError::InvalidHost)
        );
        assert_eq!(
            build_navigate_uri("https", "user@host", 443),
            Err(HttpError::InvalidHost)
        );
        assert_eq!(
            build_navigate_uri("https", "host:443", 443),
            Err(HttpError::InvalidHost)
        );
        assert_eq!(
            build_navigate_uri("https", "http:evil", 443),
            Err(HttpError::InvalidHost)
        );
        assert_eq!(
            build_navigate_uri("https", "[fd00::1", 443),
            Err(HttpError::InvalidHost)
        );
        assert_eq!(
            build_navigate_uri("https", "host name", 443),
            Err(HttpError::InvalidHost)
        );
    }

    #[test]
    fn rejects_port_zero() {
        assert_eq!(
            build_navigate_uri("https", "fw.local", 0),
            Err(HttpError::InvalidPort(0))
        );
    }

    #[test]
    fn rejects_non_http_schemes() {
        assert_eq!(
            build_navigate_uri("javascript", "fw.local", 80),
            Err(HttpError::InvalidScheme)
        );
        assert_eq!(
            build_navigate_uri("https://evil", "fw.local", 443),
            Err(HttpError::InvalidScheme)
        );
    }

    #[test]
    fn trims_surrounding_whitespace() {
        assert_eq!(
            build_navigate_uri("https", "  fw.local  ", 443).unwrap(),
            "https://fw.local:443/"
        );
    }
}
