//! Loopback bind helpers — hard fail closed outside 127.0.0.0/8 / ::1.
//!
//! The MCP Streamable HTTP surface must never bind (or accept peers from) LAN /
//! wildcard / public addresses. Tokens are never part of these helpers.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use crate::McpError;

/// Reject port `0` (ephemeral / invalid for a fixed approval URL).
pub fn validate_mcp_port(port: u16) -> Result<(), McpError> {
    if port == 0 {
        Err(McpError::InvalidPort(0))
    } else {
        Ok(())
    }
}

/// Loopback-only endpoint URL (hard-coded `127.0.0.1`, never `0.0.0.0` / LAN).
pub fn loopback_endpoint_url(port: u16) -> String {
    format!("http://127.0.0.1:{port}")
}

/// True for IPv4 / IPv6 unspecified (`0.0.0.0`, `::`) — never a valid MCP bind.
pub fn is_unspecified_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_unspecified(),
        IpAddr::V6(v6) => {
            if v6.is_unspecified() {
                return true;
            }
            // IPv4-mapped unspecified (`::ffff:0.0.0.0`) is still a wildcard.
            v6.to_ipv4_mapped()
                .is_some_and(|v4| v4.is_unspecified())
        }
    }
}

/// True for IPv4 loopback (`127.0.0.0/8`) or IPv6 loopback (`::1`).
///
/// IPv4-mapped addresses (`::ffff:x.x.x.x`) are judged by the embedded IPv4 so
/// `::ffff:8.8.8.8` fails closed and `::ffff:127.0.0.1` counts as loopback for
/// **peer** checks. Bind validation uses [`validate_loopback_bind`] instead
/// (canonical `127.0.0.0/8` / bare `::1` only; see [`loopback_v4`]).
pub fn is_loopback_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => {
            if v6.is_loopback() {
                return true;
            }
            v6.to_ipv4_mapped()
                .is_some_and(|v4| v4.is_loopback())
        }
    }
}

/// Validate a **bind** address: canonical loopback only + non-zero port.
///
/// Fail-closed: unspecified / wildcard, LAN, link-local, public,
/// **IPv4-mapped** forms (`::ffff:x.x.x.x`) — even when the embedded IPv4 is
/// loopback — and IPv6 loopback with a non-zero zone/scope id (`[::1%1]`).
/// Mapped addresses remain acceptable for **peer** checks via
/// [`is_loopback_ip`]; the listener itself must bind `127.0.0.0/8` or bare `::1`.
pub fn validate_loopback_bind(addr: SocketAddr) -> Result<(), McpError> {
    validate_mcp_port(addr.port())?;
    if !is_canonical_loopback_bind_addr(addr) {
        return Err(McpError::NonLoopbackBind(addr));
    }
    Ok(())
}

/// True only for bindable loopback sockets: IPv4 `127.0.0.0/8` or IPv6 `::1`
/// with scope id `0`.
///
/// Uses std `is_loopback` (not [`is_loopback_ip`]) so IPv4-mapped forms are
/// never accepted as bind targets — mapped loopback is peer-only.
fn is_canonical_loopback_bind_addr(addr: SocketAddr) -> bool {
    match addr {
        SocketAddr::V4(v4) => v4.ip().is_loopback(),
        SocketAddr::V6(v6) => v6.ip().is_loopback() && v6.scope_id() == 0,
    }
}

/// Parse a socket address string and require loopback + non-zero port.
///
/// Rejects hostile spellings (`0.0.0.0`, `*`, `[::]`, LAN literals, etc.) before
/// or after parse. Does not log the input beyond the typed error payload.
pub fn parse_loopback_bind(input: &str) -> Result<SocketAddr, McpError> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(McpError::InvalidBindAddress(trimmed.to_owned()));
    }

    // Common wildcard / any-interface spellings (with or without a port).
    if is_hostile_bind_literal(trimmed) {
        if let Ok(addr) = trimmed.parse::<SocketAddr>() {
            return Err(McpError::NonLoopbackBind(addr));
        }
        return Err(McpError::InvalidBindAddress(trimmed.to_owned()));
    }

    let addr: SocketAddr = trimmed
        .parse()
        .map_err(|_| McpError::InvalidBindAddress(trimmed.to_owned()))?;
    validate_loopback_bind(addr)?;
    Ok(addr)
}

/// Host-only check used when a port is supplied separately.
pub fn validate_loopback_host(host: &str) -> Result<(), McpError> {
    let trimmed = host.trim();
    if trimmed.is_empty() || is_hostile_bind_literal(trimmed) {
        return Err(McpError::InvalidBindAddress(trimmed.to_owned()));
    }
    if trimmed.eq_ignore_ascii_case("localhost") {
        return Ok(());
    }

    let ip = if let Some(rest) = trimmed.strip_prefix('[') {
        let inner = rest
            .strip_suffix(']')
            .ok_or_else(|| McpError::InvalidBindAddress(trimmed.to_owned()))?;
        inner
            .parse::<IpAddr>()
            .map_err(|_| McpError::InvalidBindAddress(trimmed.to_owned()))?
    } else {
        trimmed
            .parse::<IpAddr>()
            .map_err(|_| McpError::InvalidBindAddress(trimmed.to_owned()))?
    };

    // Dummy non-zero port — host check only cares about the IP (bind rules).
    let addr = SocketAddr::new(ip, 8765);
    if !is_canonical_loopback_bind_addr(addr) {
        return Err(McpError::NonLoopbackBind(addr));
    }
    Ok(())
}

fn is_hostile_bind_literal(input: &str) -> bool {
    let lower = input.trim().to_ascii_lowercase();
    let host = extract_bind_host(&lower);

    matches!(
        host.as_str(),
        "0.0.0.0" | "*" | "+" | "::" | "::0" | "0::0" | "0:0:0:0:0:0:0:0"
    ) || host == "::ffff:0.0.0.0"
}

/// Pull the host portion from `host`, `host:port`, or `[host]:port`.
fn extract_bind_host(input: &str) -> String {
    if let Some(rest) = input.strip_prefix('[') {
        if let Some((host, _)) = rest.split_once(']') {
            return host.to_owned();
        }
    }
    // IPv4 host:port — single ':' and numeric port.
    if let Some((host, port)) = input.rsplit_once(':') {
        if !host.is_empty()
            && !host.contains(':')
            && !port.is_empty()
            && port.chars().all(|c| c.is_ascii_digit())
        {
            return host.to_owned();
        }
    }
    input.to_owned()
}

/// Canonical IPv4 loopback socket for the MCP host (`127.0.0.1`, never `0.0.0.0`).
pub fn loopback_v4(port: u16) -> Result<SocketAddr, McpError> {
    validate_mcp_port(port)?;
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
    validate_loopback_bind(addr)?;
    Ok(addr)
}

/// Post-bind assertion: the OS-reported local address must still be loopback.
pub fn ensure_bound_loopback(local: SocketAddr) -> Result<(), McpError> {
    validate_loopback_bind(local)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;

    fn v4(a: u8, b: u8, c: u8, d: u8, port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(a, b, c, d)), port)
    }

    fn v6(ip: Ipv6Addr, port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V6(ip), port)
    }

    #[test]
    fn accepts_canonical_loopback_binds() {
        assert!(validate_loopback_bind(v4(127, 0, 0, 1, 8765)).is_ok());
        assert!(validate_loopback_bind(v4(127, 0, 0, 2, 8765)).is_ok());
        assert!(validate_loopback_bind(v6(Ipv6Addr::LOCALHOST, 8765)).is_ok());
        assert_eq!(
            loopback_v4(8765).unwrap(),
            v4(127, 0, 0, 1, 8765)
        );
        assert_eq!(loopback_endpoint_url(8765), "http://127.0.0.1:8765");
    }

    #[test]
    fn rejects_port_zero_even_on_loopback() {
        assert!(matches!(
            validate_loopback_bind(v4(127, 0, 0, 1, 0)),
            Err(McpError::InvalidPort(0))
        ));
        assert!(matches!(loopback_v4(0), Err(McpError::InvalidPort(0))));
    }

    #[test]
    fn rejects_hostile_ipv4_binds() {
        let hostile = [
            v4(0, 0, 0, 0, 8765),
            v4(192, 168, 1, 1, 8765),
            v4(10, 0, 0, 1, 8765),
            v4(172, 16, 0, 1, 8765),
            v4(8, 8, 8, 8, 8765),
            v4(169, 254, 1, 1, 8765),
            v4(224, 0, 0, 1, 8765),
            v4(255, 255, 255, 255, 8765),
        ];
        for addr in hostile {
            let err = validate_loopback_bind(addr).unwrap_err();
            assert!(
                matches!(err, McpError::NonLoopbackBind(_)),
                "expected NonLoopbackBind for {addr}, got {err:?}"
            );
            assert!(!is_loopback_ip(addr.ip()));
        }
        assert!(is_unspecified_ip(IpAddr::V4(Ipv4Addr::UNSPECIFIED)));
    }

    #[test]
    fn rejects_hostile_ipv6_and_mapped_binds() {
        let unspecified = v6(Ipv6Addr::UNSPECIFIED, 8765);
        assert!(matches!(
            validate_loopback_bind(unspecified),
            Err(McpError::NonLoopbackBind(_))
        ));
        assert!(is_unspecified_ip(unspecified.ip()));

        let mapped_public = SocketAddr::new(
            IpAddr::V6(Ipv4Addr::new(8, 8, 8, 8).to_ipv6_mapped()),
            8765,
        );
        assert!(matches!(
            validate_loopback_bind(mapped_public),
            Err(McpError::NonLoopbackBind(_))
        ));

        let mapped_unspecified = SocketAddr::new(
            IpAddr::V6(Ipv4Addr::UNSPECIFIED.to_ipv6_mapped()),
            8765,
        );
        assert!(is_unspecified_ip(mapped_unspecified.ip()));
        assert!(matches!(
            validate_loopback_bind(mapped_unspecified),
            Err(McpError::NonLoopbackBind(_))
        ));

        // Mapped loopback is fine for *peer* checks, never for bind.
        let mapped_loopback = SocketAddr::new(
            IpAddr::V6(Ipv4Addr::LOCALHOST.to_ipv6_mapped()),
            8765,
        );
        assert!(is_loopback_ip(mapped_loopback.ip()));
        assert!(matches!(
            validate_loopback_bind(mapped_loopback),
            Err(McpError::NonLoopbackBind(_))
        ));
    }

    #[test]
    fn parse_loopback_bind_accepts_loopback_strings() {
        assert_eq!(
            parse_loopback_bind("127.0.0.1:8765").unwrap(),
            v4(127, 0, 0, 1, 8765)
        );
        assert_eq!(
            parse_loopback_bind("[::1]:9001").unwrap(),
            v6(Ipv6Addr::LOCALHOST, 9001)
        );
        assert_eq!(
            parse_loopback_bind("  127.0.0.1:8765  ").unwrap(),
            v4(127, 0, 0, 1, 8765)
        );
    }

    #[test]
    fn parse_loopback_bind_rejects_hostile_strings() {
        let hostile = [
            "0.0.0.0:8765",
            "[::]:8765",
            "[::0]:8765",
            "[0000:0000:0000:0000:0000:0000:0000:0000]:8765",
            "192.168.0.1:8765",
            "10.0.0.5:8765",
            "8.8.8.8:443",
            "*:8765",
            "*",
            "+",
            "+:8765",
            "0.0.0.0",
            "::",
            "",
            "not-an-addr",
            "example.com:8765",
            "localhost:8765",
            "localhost.",
            "[::ffff:8.8.8.8]:8765",
            "[::ffff:0.0.0.0]:8765",
            "[::ffff:0:0]:8765",
            "[::FFFF:0.0.0.0]:8765",
            "[0:0:0:0:0:ffff:0.0.0.0]:8765",
            "[::ffff:127.0.0.1]:8765",
            "[0:0:0:0:0:ffff:127.0.0.1]:8765",
            "[::1%1]:8765",
            "0.0.0.0:0",
            "[::]:0",
        ];
        for input in hostile {
            assert!(
                parse_loopback_bind(input).is_err(),
                "hostile bind must fail: {input:?}"
            );
        }
    }

    #[test]
    fn validate_loopback_host_fail_closed() {
        assert!(validate_loopback_host("127.0.0.1").is_ok());
        assert!(validate_loopback_host("localhost").is_ok());
        assert!(validate_loopback_host("LOCALHOST").is_ok());
        assert!(validate_loopback_host("::1").is_ok());
        assert!(validate_loopback_host("[::1]").is_ok());

        for host in [
            "0.0.0.0",
            "*",
            "::",
            "192.168.1.1",
            "8.8.8.8",
            "",
            "localhost.",
            "::ffff:8.8.8.8",
            "::ffff:0.0.0.0",
            "::ffff:0:0",
            "::ffff:127.0.0.1",
            "[::ffff:127.0.0.1]",
        ] {
            assert!(
                validate_loopback_host(host).is_err(),
                "host must be rejected: {host:?}"
            );
        }
    }

    #[test]
    fn ensure_bound_loopback_matches_validate() {
        assert!(ensure_bound_loopback(v4(127, 0, 0, 1, 8765)).is_ok());
        assert!(ensure_bound_loopback(v6(Ipv6Addr::LOCALHOST, 8765)).is_ok());
        assert!(ensure_bound_loopback(v4(0, 0, 0, 0, 8765)).is_err());
        let mapped_loopback = SocketAddr::new(
            IpAddr::V6(Ipv4Addr::LOCALHOST.to_ipv6_mapped()),
            8765,
        );
        assert!(ensure_bound_loopback(mapped_loopback).is_err());
    }

    #[test]
    fn error_display_has_no_token_material() {
        let non_loopback = validate_loopback_bind(v4(0, 0, 0, 0, 8765)).unwrap_err();
        let non_loopback_text = non_loopback.to_string();
        assert!(non_loopback_text.contains("loopback"));
        assert!(!non_loopback_text.to_ascii_lowercase().contains("bearer"));
        assert!(!non_loopback_text.contains("token"));

        let invalid = parse_loopback_bind("not-an-addr").unwrap_err();
        assert!(matches!(invalid, McpError::InvalidBindAddress(_)));
        let invalid_text = invalid.to_string();
        assert!(!invalid_text.to_ascii_lowercase().contains("bearer"));
        assert!(!invalid_text.contains("token"));

        // Display may echo the address string; must not invent token wording.
        let mapped = parse_loopback_bind("[::ffff:8.8.8.8]:8765").unwrap_err();
        let mapped_text = mapped.to_string();
        assert!(!mapped_text.to_ascii_lowercase().contains("bearer"));
        assert!(!mapped_text.contains("token"));
    }

    #[test]
    fn rejects_ipv6_loopback_with_zone_id() {
        let zoned: SocketAddr = "[::1%1]:8765".parse().expect("zoned loopback parses");
        assert!(zoned.ip().is_loopback());
        assert!(matches!(
            validate_loopback_bind(zoned),
            Err(McpError::NonLoopbackBind(_))
        ));
        assert!(parse_loopback_bind("[::1%1]:8765").is_err());
    }

    #[test]
    fn peer_loopback_allows_mapped_but_bind_does_not() {
        let mapped = IpAddr::V6(Ipv4Addr::LOCALHOST.to_ipv6_mapped());
        assert!(is_loopback_ip(mapped));
        assert!(matches!(
            validate_loopback_bind(SocketAddr::new(mapped, 8765)),
            Err(McpError::NonLoopbackBind(_))
        ));
        assert!(validate_loopback_bind(v4(127, 0, 0, 1, 8765)).is_ok());
        assert!(validate_loopback_bind(v6(Ipv6Addr::LOCALHOST, 8765)).is_ok());
    }
}
