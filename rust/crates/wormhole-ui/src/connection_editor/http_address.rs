//! HTTP/HTTPS address field parse + host usability check.

use super::host_spec;

/// Rebuild the HTTP(S) address field from a bare host + optional port.
///
/// Bracket-wraps IPv6 literals when a port is present so the round-trip matches
/// [`parse_http_address`] / `HostSpecParser`.
pub fn format_http_address(host: &str, port: Option<u16>) -> String {
    let host = host.trim();
    match port {
        None => host.to_owned(),
        Some(port) => {
            let needs_brackets = host.contains(':')
                && !(host.starts_with('[') && host.ends_with(']') && host.len() >= 3);
            if needs_brackets {
                format!("[{host}]:{port}")
            } else {
                format!("{host}:{port}")
            }
        }
    }
}

/// Parse the web address field into bare host + optional port.
///
/// Accepts `host`, `host:port`, bracketed IPv6, and tolerates a pasted scheme/path.
/// On parse failure returns the trimmed input as host with `port = None` (C# parity).
pub fn parse_http_address(raw: &str) -> (String, Option<i32>) {
    let original = raw.trim();
    let mut trimmed = original.to_string();
    let lower = trimmed.to_ascii_lowercase();
    if let Some(rest) = lower.strip_prefix("https://") {
        trimmed = original[original.len() - rest.len()..].to_string();
    } else if let Some(rest) = lower.strip_prefix("http://") {
        trimmed = original[original.len() - rest.len()..].to_string();
    }

    if let Some(cut) = trimmed.find(['/', '?', '#']) {
        trimmed.truncate(cut);
    }
    if trimmed.is_empty() {
        return (original.to_string(), None);
    }

    match host_spec::parse(&trimmed) {
        Ok(spec) => (spec.host, spec.port),
        Err(()) => (trimmed, None),
    }
}

/// Rough stand-in for `Uri.CheckHostName` ≠ Unknown.
pub fn is_usable_http_host(host: &str) -> bool {
    let host = host.trim();
    if host.is_empty() {
        return false;
    }
    if host.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return false;
    }

    let bare = if host.starts_with('[') && host.ends_with(']') && host.len() >= 3 {
        &host[1..host.len() - 1]
    } else {
        host
    };

    if bare.is_empty() {
        return false;
    }

    // IPv6-ish. Require ≥2 colons so a failed `host:port` split (e.g. `10.0.0.1:0`
    // or `fw.local:99999`) is not mistaken for a usable IPv6 literal — `Uri.CheckHostName`
    // rejects those in the C# editor.
    if bare.contains(':') {
        let colon_count = bare.bytes().filter(|&b| b == b':').count();
        if colon_count < 2 {
            return false;
        }
        if bare.starts_with(':') && !bare.starts_with("::") {
            return false;
        }
        return bare
            .chars()
            .all(|c| c.is_ascii_hexdigit() || c == ':' || c == '.');
    }

    // IPv4
    if bare.chars().all(|c| c.is_ascii_digit() || c == '.') {
        let parts: Vec<_> = bare.split('.').collect();
        if parts.len() == 4 {
            return parts.iter().all(|p| {
                !p.is_empty()
                    && p.len() <= 3
                    && p.parse::<u16>().is_ok_and(|n| n <= 255)
            });
        }
        // Not a clean IPv4 — fall through to DNS rules (rejects "1.2").
    }

    // DNS hostname labels
    if bare.starts_with('-') || bare.ends_with('-') || bare.starts_with('.') || bare.ends_with('.')
    {
        return false;
    }
    bare.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-')
            && !label.starts_with('-')
            && !label.ends_with('-')
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_scheme_and_path() {
        assert_eq!(
            parse_http_address("https://fw.local:8443/login"),
            ("fw.local".into(), Some(8443))
        );
    }

    #[test]
    fn format_round_trips_ipv4_and_ipv6() {
        assert_eq!(format_http_address("fw.local", None), "fw.local");
        assert_eq!(format_http_address("fw.local", Some(8443)), "fw.local:8443");
        assert_eq!(format_http_address("fd00::1", Some(443)), "[fd00::1]:443");
        assert_eq!(
            parse_http_address(&format_http_address("fd00::1", Some(443))),
            ("fd00::1".into(), Some(443))
        );
    }

    #[test]
    fn host_usability() {
        assert!(is_usable_http_host("fw.local"));
        assert!(is_usable_http_host("10.0.0.1"));
        assert!(is_usable_http_host("fd00::1"));
        assert!(is_usable_http_host("[fd00::1]"));
        assert!(!is_usable_http_host(""));
        assert!(!is_usable_http_host("   "));
        assert!(!is_usable_http_host(":8443"));
        // Failed host:port residues must not pass as IPv6.
        assert!(!is_usable_http_host("10.0.0.1:0"));
        assert!(!is_usable_http_host("10.0.0.1:99999"));
        assert!(!is_usable_http_host("fw.local:99999"));
    }
}
