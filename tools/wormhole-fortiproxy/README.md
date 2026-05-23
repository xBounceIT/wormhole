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

1. `POST https://<host>:<port>/remote/logincheck` form-encoded with `username`, `credential`,
   optional `realm`, `ajax=1`, `just_logged_in=1`. On 2FA challenge the response body
   contains `ret=...,reqid=...,polid=...,grp=...,portal=...,magic=...` — these are echoed
   back with `code=<TOTP>` to complete the second factor.
2. Extract `SVPNCOOKIE` from the response `Set-Cookie` header.
3. `GET /remote/fortisslvpn_xml` returns assigned IP / DNS / MTU as XML.
4. `GET /remote/sslvpn-tunnel` (no response body — the connection upgrades to PPP-over-TLS).
5. PPP frames flow with the 6-byte Fortinet encap header (`[total_len][0x5050][payload_len]`).
   LCP + IPCP negotiate the IPv4 address handed back by the gateway; from then on, IPv4
   packets are decapsulated into a gVisor netstack `channel.Endpoint`.

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
