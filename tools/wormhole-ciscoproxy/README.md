# wormhole-ciscoproxy

Userspace Cisco Secure Client (formerly AnyConnect) SSL VPN sidecar for Wormhole. Talks the
Cisco AnyConnect SSL VPN protocol (aggregate-auth XML login + CSTP tunnel) entirely in user
space — no TUN driver, no admin rights, no OS-level effects — and exposes the resulting virtual
network through a local SOCKS5 listener on `127.0.0.1`. It does **not** drive the locally
installed Cisco Secure Client (which builds a system-wide, single-session tunnel and can't expose
a loopback SOCKS5); it speaks the protocol directly, the same way `openconnect` does.

Wormhole spawns one of these per active connection that has a Cisco Secure Client tunnel
configured. Lifetime is bound to stdin: the parent writes a JSON config on the first line, reads
`READY <port>` from stdout, and lets stdin stay open. When the parent dies (or closes stdin), the
sidecar shuts down and the TLS connection tears down.

## Wire protocol with the parent

- **stdin**: one JSON object on the first line, then EOF acts as the shutdown signal.
- **stdout**: a single line `READY <port>\n` once the SOCKS5 listener is up.
- **stderr**: structured log lines (one per event, free-form text).

Config fields (lower_snake_case): `host`, `port`, `username`, `password`, `group`,
`secondary_password`, `totp_secret`, `trust_server_certificate`, `server_cert_sha256_pin`.

## AnyConnect protocol

1. `POST https://<host>:<port>/` with an XML `<config-auth type="init">` body (headers
   `X-Aggregate-Auth: 1`, AnyConnect User-Agent). The gateway answers with the primary auth
   `<form>` plus an `<opaque>` session blob and any group list.
2. `POST` an `<config-auth type="auth-reply">` echoing the opaque blob verbatim and filling the
   form: username into the text input, password into the password input. A second form (2FA
   challenge) is answered with a generated TOTP code (`totp_secret`) or a static
   `secondary_password`.
3. On `<auth id="success">` the gateway sets a `webvpn` session cookie.
4. `CONNECT /CSTP HTTP/1.1` over a fresh TLS connection with `Cookie: webvpn=…` and the
   `X-CSTP-*` request headers. The `200 CONNECTED` response carries `X-CSTP-Address`,
   `X-CSTP-MTU`, `X-CSTP-DNS`, `X-CSTP-DPD`.
5. Data flows as STF-framed packets — an 8-byte header `['S','T','F',0x01][len:u16][type][0x00]`.
   `AC_PKT_DATA` payloads are raw IPv4 packets, injected into a gVisor netstack
   `channel.Endpoint`; `AC_PKT_DPD_OUT` probes are answered with `AC_PKT_DPD_RESP`.

Hostname targets received over SOCKS5 resolve through the gateway-pushed DNS servers
(`X-CSTP-DNS`), failing closed when none are pushed so queries never leak to the host resolver
(same model as the Fortinet sidecar).

References for the wire format:
- openconnect's `auth.c` / `cstp.c` (LGPL-2.1) — aggregate-auth XML flow and STF framing.

## Not supported (v1)

- SAML single sign-on (embedded or external browser).
- Client-certificate authentication.
- Endpoint posture assessment (CSD / HostScan). Gateways that enforce it will reject the login.
- IPv6-only tunnels (IPv4 assigned address required).

## Building

```
cd tools/wormhole-ciscoproxy
go build -trimpath -ldflags "-s -w" -o ../../bin/wormhole-ciscoproxy.exe .
```

Pure Go (no CGO), so it cross-compiles cleanly for both `windows/amd64` and `windows/arm64`.

## Mock mode

Pass `--mock` to skip the AnyConnect handshake and dial targets via the OS resolver/sockets.
Used for smoke-testing the stdin/READY/SOCKS5 wire protocol without a real gateway.
