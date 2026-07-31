//! Minimal RFC 1928 SOCKS5 client (no-auth + CONNECT).
//!
//! Mirrors `Services/Tunneling/Socks5Client.cs`. Sized for in-process tunnel
//! sidecars that expose SOCKS5 on `127.0.0.1`.

use std::net::IpAddr;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::{Socks5Endpoint, TunnelError};

const VER: u8 = 0x05;
const METHOD_NO_AUTH: u8 = 0x00;
const CMD_CONNECT: u8 = 0x01;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;
const REP_SUCCESS: u8 = 0x00;

/// Validate `host:port` for SOCKS CONNECT / local forwarder targets.
///
/// Returns the trimmed host. Rejects empty/whitespace hosts and port `0`.
pub(crate) fn validate_target<'a>(host: &'a str, port: u16) -> Result<&'a str, TunnelError> {
    let trimmed = host.trim();
    if trimmed.is_empty() {
        return Err(TunnelError::InvalidTarget {
            host: host.to_string(),
            port,
            reason: "target host required".into(),
        });
    }
    if port == 0 {
        return Err(TunnelError::InvalidTarget {
            host: trimmed.to_string(),
            port,
            reason: "target port must be 1..=65535".into(),
        });
    }
    Ok(trimmed)
}

/// Connect through a local SOCKS5 endpoint to `target_host`:`target_port`.
pub struct Socks5Client;

impl Socks5Client {
    /// Dial `target_host`:`target_port` via `socks` (TCP CONNECT, no-auth).
    ///
    /// Address encoding:
    /// - IPv4 literal → ATYP=0x01
    /// - IPv6 literal → ATYP=0x04 (must not go through IDNA; bracketed form accepted)
    /// - hostname → ATYP=0x03 DOMAINNAME (Punycode for IDN)
    pub async fn connect(
        socks: Socks5Endpoint,
        target_host: &str,
        target_port: u16,
    ) -> Result<TcpStream, TunnelError> {
        let host = validate_target(target_host, target_port)?;
        let (atyp, addr_bytes) = encode_target_addr(host)?;

        let mut stream = TcpStream::connect(socks.addr)
            .await
            .map_err(|e| TunnelError::Socks5(format!("connect to SOCKS endpoint failed: {e}")))?;
        stream.set_nodelay(true).ok();

        // Greeting: VER=5, NMETHODS=1, METHOD=0 (no auth)
        stream
            .write_all(&[VER, 0x01, METHOD_NO_AUTH])
            .await
            .map_err(|e| TunnelError::Socks5(format!("greeting write failed: {e}")))?;

        let mut greeting_resp = [0u8; 2];
        stream
            .read_exact(&mut greeting_resp)
            .await
            .map_err(|e| TunnelError::Socks5(format!("greeting read failed: {e}")))?;
        if greeting_resp[0] != VER {
            return Err(TunnelError::Socks5(format!(
                "unexpected version 0x{:02x} in greeting reply",
                greeting_resp[0]
            )));
        }
        if greeting_resp[1] != METHOD_NO_AUTH {
            return Err(TunnelError::Socks5(format!(
                "server selected unsupported auth method 0x{:02x}",
                greeting_resp[1]
            )));
        }

        // CONNECT request: [VER, CMD, RSV, ATYP, ADDR..., PORT]
        let mut req = Vec::with_capacity(4 + addr_bytes.len() + 2);
        req.extend_from_slice(&[VER, CMD_CONNECT, 0x00, atyp]);
        req.extend_from_slice(&addr_bytes);
        req.extend_from_slice(&target_port.to_be_bytes());
        stream
            .write_all(&req)
            .await
            .map_err(|e| TunnelError::Socks5(format!("CONNECT write failed: {e}")))?;

        let mut head = [0u8; 4];
        stream
            .read_exact(&mut head)
            .await
            .map_err(|e| TunnelError::Socks5(format!("CONNECT reply read failed: {e}")))?;
        if head[0] != VER {
            return Err(TunnelError::Socks5(format!(
                "unexpected version 0x{:02x} in connect reply",
                head[0]
            )));
        }

        let failure_detail = read_bound_address_or_detail(&mut stream, head[3]).await?;
        if head[1] != REP_SUCCESS {
            let mut message = format!(
                "CONNECT failed with reply code 0x{:02x} ({})",
                head[1],
                describe_reply(head[1])
            );
            if let Some(detail) = failure_detail.filter(|d| !d.trim().is_empty()) {
                message.push_str(": ");
                message.push_str(&detail);
            }
            return Err(TunnelError::Socks5(message));
        }

        Ok(stream)
    }
}

fn encode_target_addr(host: &str) -> Result<(u8, Vec<u8>), TunnelError> {
    // .NET IPAddress.TryParse accepts bracketed IPv6; strip so literals never hit IDNA.
    let host = unbracket_ipv6_literal(host);

    if let Ok(ip) = host.parse::<IpAddr>() {
        return match ip {
            IpAddr::V4(v4) => Ok((ATYP_IPV4, v4.octets().to_vec())),
            IpAddr::V6(v6) => Ok((ATYP_IPV6, v6.octets().to_vec())),
        };
    }

    // DOMAINNAME is ASCII-only per RFC 1928. Punycode-convert IDN hostnames.
    let ascii_host = if host.is_ascii() {
        host.to_string()
    } else {
        idna::domain_to_ascii(host).map_err(|e| TunnelError::InvalidTarget {
            host: host.to_string(),
            port: 0,
            reason: format!("not a valid IDN/ASCII hostname or IP literal: {e}"),
        })?
    };

    let bytes = ascii_host.as_bytes();
    if bytes.is_empty() || bytes.len() > 255 {
        return Err(TunnelError::InvalidTarget {
            host: host.to_string(),
            port: 0,
            reason: "target host too long for SOCKS5 DOMAINNAME (>255)".into(),
        });
    }

    let mut addr = Vec::with_capacity(1 + bytes.len());
    addr.push(bytes.len() as u8);
    addr.extend_from_slice(bytes);
    Ok((ATYP_DOMAIN, addr))
}

/// Strip `[…]` only when the inner value looks like an IPv6 literal (contains `:`).
fn unbracket_ipv6_literal(host: &str) -> &str {
    if let Some(inner) = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
    {
        if inner.contains(':') {
            return inner;
        }
    }
    host
}

async fn read_bound_address_or_detail(
    stream: &mut TcpStream,
    atyp: u8,
) -> Result<Option<String>, TunnelError> {
    match atyp {
        ATYP_IPV4 => {
            let mut skip = [0u8; 4 + 2];
            stream
                .read_exact(&mut skip)
                .await
                .map_err(|e| TunnelError::Socks5(format!("bound IPv4 read failed: {e}")))?;
            Ok(None)
        }
        ATYP_IPV6 => {
            let mut skip = [0u8; 16 + 2];
            stream
                .read_exact(&mut skip)
                .await
                .map_err(|e| TunnelError::Socks5(format!("bound IPv6 read failed: {e}")))?;
            Ok(None)
        }
        ATYP_DOMAIN => {
            let mut len_buf = [0u8; 1];
            stream
                .read_exact(&mut len_buf)
                .await
                .map_err(|e| TunnelError::Socks5(format!("bound domain len read failed: {e}")))?;
            let addr_len = len_buf[0] as usize;
            let mut address_and_port = vec![0u8; addr_len + 2];
            stream
                .read_exact(&mut address_and_port)
                .await
                .map_err(|e| TunnelError::Socks5(format!("bound domain read failed: {e}")))?;
            if addr_len == 0 {
                Ok(None)
            } else {
                Ok(Some(
                    String::from_utf8_lossy(&address_and_port[..addr_len]).into_owned(),
                ))
            }
        }
        other => Err(TunnelError::Socks5(format!(
            "unknown bound address type 0x{other:02x}"
        ))),
    }
}

fn describe_reply(code: u8) -> &'static str {
    match code {
        0x01 => "general SOCKS server failure",
        0x02 => "connection not allowed by ruleset",
        0x03 => "network unreachable",
        0x04 => "host unreachable",
        0x05 => "connection refused",
        0x06 => "TTL expired",
        0x07 => "command not supported",
        0x08 => "address type not supported",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    struct FakeSocksState {
        last_atyp: u8,
        last_host: String,
        last_port: u16,
    }

    async fn spawn_fake_socks(
        reply_code: u8,
        reply_detail: Option<&str>,
    ) -> (Socks5Endpoint, Arc<Mutex<FakeSocksState>>, tokio::task::JoinHandle<()>) {
        spawn_fake_socks_with_auth(reply_code, reply_detail, METHOD_NO_AUTH, None).await
    }

    async fn spawn_fake_socks_with_auth(
        reply_code: u8,
        reply_detail: Option<&str>,
        selected_method: u8,
        reply_override: Option<Vec<u8>>,
    ) -> (Socks5Endpoint, Arc<Mutex<FakeSocksState>>, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let state = Arc::new(Mutex::new(FakeSocksState {
            last_atyp: 0,
            last_host: String::new(),
            last_port: 0,
        }));
        let state_clone = state.clone();
        let detail = reply_detail.map(str::to_string);
        let handle = tokio::spawn(async move {
            let (mut client, _) = listener.accept().await.unwrap();
            let mut hdr = [0u8; 2];
            client.read_exact(&mut hdr).await.unwrap();
            let mut methods = vec![0u8; hdr[1] as usize];
            client.read_exact(&mut methods).await.unwrap();
            client.write_all(&[VER, selected_method]).await.unwrap();
            if selected_method != METHOD_NO_AUTH {
                return;
            }

            let mut req = [0u8; 4];
            client.read_exact(&mut req).await.unwrap();
            let atyp = req[3];
            let parsed_host = match atyp {
                ATYP_IPV4 => {
                    let mut ip = [0u8; 4];
                    client.read_exact(&mut ip).await.unwrap();
                    Ipv4Addr::from(ip).to_string()
                }
                ATYP_DOMAIN => {
                    let mut len = [0u8; 1];
                    client.read_exact(&mut len).await.unwrap();
                    let mut host = vec![0u8; len[0] as usize];
                    client.read_exact(&mut host).await.unwrap();
                    String::from_utf8(host).unwrap()
                }
                ATYP_IPV6 => {
                    let mut ip = [0u8; 16];
                    client.read_exact(&mut ip).await.unwrap();
                    Ipv6Addr::from(ip).to_string()
                }
                _ => return,
            };
            let mut port_buf = [0u8; 2];
            client.read_exact(&mut port_buf).await.unwrap();
            let port = u16::from_be_bytes(port_buf);
            {
                let mut g = state_clone.lock().unwrap();
                g.last_atyp = atyp;
                g.last_host = parsed_host;
                g.last_port = port;
            }

            if let Some(raw) = reply_override {
                let _ = client.write_all(&raw).await;
                return;
            }

            if reply_code != REP_SUCCESS {
                if let Some(detail) = detail {
                    let detail_bytes = detail.as_bytes();
                    assert!(detail_bytes.len() <= 255);
                    let mut reply = vec![VER, reply_code, 0x00, ATYP_DOMAIN];
                    reply.push(detail_bytes.len() as u8);
                    reply.extend_from_slice(detail_bytes);
                    reply.extend_from_slice(&0u16.to_be_bytes());
                    client.write_all(&reply).await.unwrap();
                } else {
                    client
                        .write_all(&[VER, reply_code, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0])
                        .await
                        .unwrap();
                }
                return;
            }

            client
                .write_all(&[VER, REP_SUCCESS, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();

            let mut msg = [0u8; 4];
            if client.read_exact(&mut msg).await.is_ok() && &msg == b"ping" {
                let _ = client.write_all(b"pong").await;
            }
        });
        (Socks5Endpoint::new(addr), state, handle)
    }

    #[tokio::test]
    async fn connect_negotiates_no_auth_and_forwards_bytes() {
        let (socks, state, handle) = spawn_fake_socks(REP_SUCCESS, None).await;
        let mut stream = Socks5Client::connect(socks, "target.example", 22)
            .await
            .unwrap();
        stream.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"pong");
        handle.await.unwrap();
        let g = state.lock().unwrap();
        assert_eq!(g.last_host, "target.example");
        assert_eq!(g.last_port, 22);
        assert_eq!(g.last_atyp, ATYP_DOMAIN);
    }

    #[tokio::test]
    async fn connect_throws_on_error_reply() {
        let (socks, _, handle) = spawn_fake_socks(0x05, None).await;
        let err = Socks5Client::connect(socks, "any.example", 1234)
            .await
            .unwrap_err();
        assert!(matches!(err, TunnelError::Socks5(_)));
        assert!(format!("{err}").contains("0x05"));
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn connect_includes_failure_detail() {
        let detail = "no data-plane response from tunnel (dial_id=7 target=192.0.2.10:22)";
        let (socks, _, handle) = spawn_fake_socks(0x04, Some(detail)).await;
        let err = Socks5Client::connect(socks, "192.0.2.10", 22)
            .await
            .unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("0x04"));
        assert!(msg.contains("no data-plane response"));
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn connect_sends_ipv4_as_atyp1() {
        let (socks, state, handle) = spawn_fake_socks(REP_SUCCESS, None).await;
        let mut stream = Socks5Client::connect(socks, "192.0.2.10", 22)
            .await
            .unwrap();
        stream.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf).await.unwrap();
        handle.await.unwrap();
        let g = state.lock().unwrap();
        assert_eq!(g.last_atyp, ATYP_IPV4);
        assert_eq!(g.last_host, "192.0.2.10");
    }

    #[tokio::test]
    async fn connect_sends_ipv6_as_atyp4() {
        let (socks, state, handle) = spawn_fake_socks(REP_SUCCESS, None).await;
        let mut stream = Socks5Client::connect(socks, "2001:db8::10", 22)
            .await
            .unwrap();
        stream.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf).await.unwrap();
        handle.await.unwrap();
        let g = state.lock().unwrap();
        assert_eq!(g.last_atyp, ATYP_IPV6);
        assert_eq!(
            g.last_host.parse::<IpAddr>().unwrap(),
            "2001:db8::10".parse::<IpAddr>().unwrap()
        );
    }

    #[tokio::test]
    async fn connect_accepts_bracketed_ipv6() {
        let (socks, state, handle) = spawn_fake_socks(REP_SUCCESS, None).await;
        let mut stream = Socks5Client::connect(socks, "[2001:db8::10]", 22)
            .await
            .unwrap();
        stream.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf).await.unwrap();
        handle.await.unwrap();
        let g = state.lock().unwrap();
        assert_eq!(g.last_atyp, ATYP_IPV6);
        assert_eq!(
            g.last_host.parse::<IpAddr>().unwrap(),
            "2001:db8::10".parse::<IpAddr>().unwrap()
        );
    }

    #[tokio::test]
    async fn connect_punycodes_idn_hostname() {
        let (socks, state, handle) = spawn_fake_socks(REP_SUCCESS, None).await;
        let mut stream = Socks5Client::connect(socks, "münchen.example", 443)
            .await
            .unwrap();
        stream.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf).await.unwrap();
        handle.await.unwrap();
        let g = state.lock().unwrap();
        assert_eq!(g.last_atyp, ATYP_DOMAIN);
        assert_eq!(g.last_host, "xn--mnchen-3ya.example");
        assert_eq!(g.last_port, 443);
    }

    #[tokio::test]
    async fn connect_rejects_empty_host_and_port_zero() {
        let socks = Socks5Endpoint::loopback(9);
        let empty = Socks5Client::connect(socks, "   ", 22).await.unwrap_err();
        assert!(matches!(empty, TunnelError::InvalidTarget { .. }));
        let port0 = Socks5Client::connect(socks, "h.example", 0)
            .await
            .unwrap_err();
        assert!(matches!(
            port0,
            TunnelError::InvalidTarget { port: 0, .. }
        ));
    }

    #[tokio::test]
    async fn connect_rejects_non_no_auth_method() {
        let (socks, _, handle) =
            spawn_fake_socks_with_auth(REP_SUCCESS, None, 0x02, None).await;
        let err = Socks5Client::connect(socks, "any.example", 22)
            .await
            .unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("unsupported auth method"));
        assert!(msg.contains("0x02"));
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn connect_rejects_method_none_acceptable() {
        let (socks, _, handle) =
            spawn_fake_socks_with_auth(REP_SUCCESS, None, 0xFF, None).await;
        let err = Socks5Client::connect(socks, "any.example", 22)
            .await
            .unwrap_err();
        assert!(format!("{err}").contains("0xff"));
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn connect_fails_on_truncated_reply() {
        let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let (mut client, _) = listener.accept().await.unwrap();
            let mut hdr = [0u8; 2];
            client.read_exact(&mut hdr).await.unwrap();
            let mut methods = vec![0u8; hdr[1] as usize];
            client.read_exact(&mut methods).await.unwrap();
            // Greeting OK, then only 2 of 4 CONNECT reply bytes.
            client.write_all(&[VER, METHOD_NO_AUTH]).await.unwrap();
            let mut req_head = [0u8; 4];
            client.read_exact(&mut req_head).await.unwrap();
            // Drain rest of CONNECT then send truncated reply.
            let mut drain = [0u8; 256];
            let _ = client.read(&mut drain).await;
            let _ = client.write_all(&[VER, REP_SUCCESS]).await;
            // Close without the rest.
        });
        let err = Socks5Client::connect(Socks5Endpoint::new(addr), "h.example", 22)
            .await
            .unwrap_err();
        assert!(matches!(err, TunnelError::Socks5(_)));
        assert!(format!("{err}").contains("CONNECT reply read failed"));
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn connect_fails_on_truncated_bound_address() {
        // Full CONNECT head + ATYP IPv4, but only 2 of 6 bound bytes then close.
        let raw = vec![VER, REP_SUCCESS, 0x00, ATYP_IPV4, 0, 0];
        let (socks, _, handle) =
            spawn_fake_socks_with_auth(REP_SUCCESS, None, METHOD_NO_AUTH, Some(raw)).await;
        let err = Socks5Client::connect(socks, "h.example", 22)
            .await
            .unwrap_err();
        assert!(format!("{err}").contains("bound IPv4 read failed"));
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn connect_rejects_unknown_bound_atyp() {
        // VER, REP, RSV, ATYP=0x99 — unknown; no further bytes.
        let raw = vec![VER, REP_SUCCESS, 0x00, 0x99];
        let (socks, _, handle) =
            spawn_fake_socks_with_auth(REP_SUCCESS, None, METHOD_NO_AUTH, Some(raw)).await;
        let err = Socks5Client::connect(socks, "h.example", 22)
            .await
            .unwrap_err();
        assert!(format!("{err}").contains("unknown bound address type"));
        handle.await.unwrap();
    }

    #[test]
    fn validate_target_rejects_empty_and_port_zero() {
        assert!(validate_target("", 22).is_err());
        assert!(validate_target(" \t ", 22).is_err());
        assert!(validate_target("h", 0).is_err());
        assert_eq!(validate_target("  h  ", 22).unwrap(), "h");
    }

    #[test]
    fn encode_rejects_oversized_hostname() {
        let huge = "a".repeat(256);
        let err = encode_target_addr(&huge).unwrap_err();
        assert!(matches!(err, TunnelError::InvalidTarget { .. }));
        assert!(format!("{err}").contains("too long"));
    }
}
