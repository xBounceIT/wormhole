# wormhole-fortiproxy

Userspace Fortinet SSL VPN sidecar for Wormhole. Talks the FortiGate SSL VPN protocol
(PPP-over-TLS, v1 wire format) entirely in user space — no TUN driver, no admin rights,
no OS-level effects — and exposes the resulting virtual network through a local SOCKS5
listener on `127.0.0.1`.

Wormhole spawns one of these per active connection that has a Fortinet tunnel configured.
Lifetime is bound to stdin: the parent writes a JSON config on the first line, reads
`READY <port>` from stdout, and lets stdin stay open. When the parent dies (or closes
stdin), the sidecar shuts down and the TLS connection tears down.

## Wire protocol with the parent

- **stdin**: one JSON object on the first line, then EOF acts as the shutdown signal.
- **stdout**: a single line `READY <port>\n` once the SOCKS5 listener is up.
- **stderr**: structured log lines (one per event, free-form text).

## FortiGate protocol

1. Establish `SVPNCOOKIE` using exactly one authentication mode:
   - Credentials: `POST https://<host>:<port>/remote/logincheck` with `username`,
     `credential`, optional `realm`, `ajax=1`, and `just_logged_in=1`. If the
     response contains a 2FA challenge, echo its challenge fields with `code=<TOTP>`.
   - External-browser SAML: exchange the ephemeral `saml_auth_id` with
     `GET /remote/saml/auth_id?id=...` and read `SVPNCOOKIE` from the response.
   - Embedded-WebView2 SAML: seed the cookie jar directly from the ephemeral
     `svpn_cookie` supplied by the parent.
2. `GET /remote/fortisslvpn_xml` returns assigned IP / DNS / MTU as XML.
3. `GET /remote/sslvpn-tunnel` (no response body — the connection upgrades to PPP-over-TLS).
4. PPP frames flow with the 6-byte Fortinet encap header (`[total_len][0x5050][payload_len]`).
   LCP + IPCP negotiate the IPv4 address handed back by the gateway; from then on, IPv4
   packets are decapsulated into a gVisor netstack `channel.Endpoint`.

Credentials, `saml_auth_id`, and `svpn_cookie` are mutually exclusive. SAML
material arrives only in the one-line stdin JSON and is neither persisted nor
included in logs or errors.

References for the wire format:
- openconnect's `fortinet.c` (LGPL-2.1) — login flow, challenge handling, tunnel upgrade.
- openconnect's `ppp.c`        (LGPL-2.1) — Fortinet PPP encapsulation header.

## Building

```
cd tools/wormhole-fortiproxy
go build -trimpath -ldflags "-s -w" -o ../../bin/wormhole-fortiproxy.exe .
```

## Mock mode

Pass `--mock` to skip the FortiGate handshake and dial targets via the OS resolver/sockets.
Used by Wormhole's integration tests so CI doesn't need a real FortiGate.
