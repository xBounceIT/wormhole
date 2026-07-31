//! Sidecar stdout handshake lines (`READY` / `SOCKS`).

use crate::TunnelError;

/// Maximum accepted handshake line length (bytes), including trailing newline.
/// Production lines are `READY <port>\n` (~14 bytes); anything larger is treated as hostile.
pub const MAX_HANDSHAKE_LINE_BYTES: usize = 64;

/// Parse a sidecar stdout handshake line into a SOCKS5 listen port.
///
/// Accepts the production form `READY <port>` (all Go sidecars under `tools/`) and the
/// alternate `SOCKS <port>` spelling so callers / tests can treat them uniformly.
///
/// Rejects trailing garbage, control characters, oversized input, and port `0`.
pub fn parse_ready_or_socks_line(line: &str) -> Result<u16, TunnelError> {
    if line.len() > MAX_HANDSHAKE_LINE_BYTES {
        return Err(TunnelError::Establish(
            "sidecar handshake line exceeded maximum length".into(),
        ));
    }
    if line.chars().any(|c| c.is_control() && c != '\n' && c != '\r' && c != '\t') {
        return Err(TunnelError::Establish(
            "sidecar handshake line contains control characters".into(),
        ));
    }

    let line = line.trim();
    if line.is_empty() {
        return Err(TunnelError::Establish(
            "sidecar produced an empty handshake line".into(),
        ));
    }

    let port_str = if let Some(rest) = line.strip_prefix("READY ") {
        rest.trim()
    } else if let Some(rest) = line.strip_prefix("SOCKS ") {
        rest.trim()
    } else {
        return Err(TunnelError::Establish(format!(
            "sidecar produced unexpected handshake line: {}",
            redact_handshake_line(line)
        )));
    };

    // Digits only — rejects `18080 evil`, signs, underscores, and Unicode digits.
    if port_str.is_empty() || !port_str.bytes().all(|b| b.is_ascii_digit()) {
        return Err(TunnelError::Establish(format!(
            "sidecar handshake port is not a valid u16: {}",
            redact_handshake_line(line)
        )));
    }

    let port: u16 = port_str.parse().map_err(|_| {
        TunnelError::Establish(format!(
            "sidecar handshake port is not a valid u16: {}",
            redact_handshake_line(line)
        ))
    })?;
    if port == 0 {
        return Err(TunnelError::Establish(format!(
            "sidecar handshake port must be 1..=65535, got 0 (line {})",
            redact_handshake_line(line)
        )));
    }
    Ok(port)
}

/// Truncate / sanitize a handshake line before embedding it in an error string.
fn redact_handshake_line(line: &str) -> String {
    const MAX_DISPLAY: usize = 48;
    let mut cleaned: String = line
        .chars()
        .map(|c| {
            if c.is_ascii_graphic() || c == ' ' {
                c
            } else {
                '?'
            }
        })
        .take(MAX_DISPLAY)
        .collect();
    if line.chars().count() > MAX_DISPLAY {
        cleaned.push('…');
    }
    cleaned
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ready_line() {
        assert_eq!(parse_ready_or_socks_line("READY 18080").unwrap(), 18080);
        assert_eq!(parse_ready_or_socks_line("  READY 1\n").unwrap(), 1);
        assert_eq!(parse_ready_or_socks_line("READY 65535").unwrap(), 65535);
    }

    #[test]
    fn parses_socks_line() {
        assert_eq!(parse_ready_or_socks_line("SOCKS 9050").unwrap(), 9050);
        assert_eq!(parse_ready_or_socks_line("SOCKS  4242").unwrap(), 4242);
    }

    #[test]
    fn rejects_garbage_and_zero() {
        assert!(parse_ready_or_socks_line("OK 1").is_err());
        assert!(parse_ready_or_socks_line("READY").is_err());
        assert!(parse_ready_or_socks_line("READY abc").is_err());
        assert!(parse_ready_or_socks_line("READY 0").is_err());
        assert!(parse_ready_or_socks_line("READY 70000").is_err());
        assert!(parse_ready_or_socks_line("").is_err());
        assert!(parse_ready_or_socks_line("READY 18080 evil").is_err());
        assert!(parse_ready_or_socks_line("READY +1").is_err());
        assert!(parse_ready_or_socks_line("ready 1").is_err());
        assert!(parse_ready_or_socks_line("READY\t1").is_err());
    }

    #[test]
    fn rejects_oversized_and_control_chars() {
        let huge = "A".repeat(MAX_HANDSHAKE_LINE_BYTES + 1);
        assert!(parse_ready_or_socks_line(&huge).is_err());
        assert!(parse_ready_or_socks_line("READY 1\u{0000}").is_err());
        assert!(parse_ready_or_socks_line("READY 1\u{001b}").is_err());
    }

    #[test]
    fn error_messages_do_not_echo_unbounded_payload() {
        let evil = format!("READY 1 {}", "x".repeat(200));
        let err = parse_ready_or_socks_line(&evil).unwrap_err();
        let rendered = format!("{err}");
        assert!(!rendered.contains(&"x".repeat(200)));
        assert!(rendered.len() < 200, "{rendered}");
    }
}
