//! Minimal `HostSpecParser` port for HTTP address splitting.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostSpec {
    pub host: String,
    pub port: Option<i32>,
}

/// Parse `host`, `host:port`, `[ipv6]:port`, or a bare IPv6 literal.
pub fn parse(input: &str) -> Result<HostSpec, ()> {
    let s = input.trim();
    if s.is_empty() {
        return Err(());
    }

    // Bracketed: [host]:port
    if s.starts_with('[') {
        let close = s.find(']').ok_or(())?;
        let host = &s[1..close];
        if host.is_empty() {
            return Err(());
        }
        let rest = &s[close + 1..];
        if rest.is_empty() {
            return Ok(HostSpec {
                host: host.to_string(),
                port: None,
            });
        }
        if let Some(port_text) = rest.strip_prefix(':')
            && let Some(port) = parse_port(port_text)
        {
            return Ok(HostSpec {
                host: host.to_string(),
                port: Some(port),
            });
        }
        return Err(());
    }

    // Bracketless IPv6: more than one ':' → whole string is host.
    if s.chars().filter(|c| *c == ':').count() > 1 {
        return Ok(HostSpec {
            host: s.to_string(),
            port: None,
        });
    }

    if let Some(colon) = s.rfind(':')
        && colon > 0
        && let Some(port) = parse_port(&s[colon + 1..])
    {
        let host = &s[..colon];
        if host.is_empty() {
            return Err(());
        }
        return Ok(HostSpec {
            host: host.to_string(),
            port: Some(port),
        });
    }

    Ok(HostSpec {
        host: s.to_string(),
        port: None,
    })
}

fn parse_port(text: &str) -> Option<i32> {
    let port: i32 = text.parse().ok()?;
    (1..=65535).contains(&port).then_some(port)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_port_and_ipv6() {
        assert_eq!(
            parse("10.0.0.1:8443").unwrap(),
            HostSpec {
                host: "10.0.0.1".into(),
                port: Some(8443),
            }
        );
        assert_eq!(
            parse("[fd00::1]:443").unwrap(),
            HostSpec {
                host: "fd00::1".into(),
                port: Some(443),
            }
        );
        assert_eq!(
            parse("fd00::1").unwrap(),
            HostSpec {
                host: "fd00::1".into(),
                port: None,
            }
        );
    }
}
