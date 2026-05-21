# wormhole-wgproxy

Userspace WireGuard sidecar for Wormhole. Brings up a wireguard-go device entirely in user
space via gVisor netstack (no TUN driver, no admin rights, no OS-level effects) and exposes
the resulting virtual network through a local SOCKS5 listener on `127.0.0.1`.

Wormhole spawns one of these per active connection that has a tunnel configured. The lifetime
is bound to stdin: the parent writes a JSON config on the first line, reads `READY <port>` from
stdout, and lets stdin stay open. When the parent dies (or closes stdin), the sidecar shuts
down and the WireGuard device tears down.

## Wire protocol

- **stdin**: one JSON object on the first line, then EOF acts as the shutdown signal.
- **stdout**: a single line `READY <port>\n` once the SOCKS5 listener is up.
- **stderr**: structured log lines (one per event, free-form text).

## Building

```
cd tools/wormhole-wgproxy
go build -trimpath -ldflags "-s -w" -o ../../bin/wormhole-wgproxy.exe .
```

Cross-build for arm64:

```
GOOS=windows GOARCH=arm64 go build -trimpath -ldflags "-s -w" -o ../../bin/arm64/wormhole-wgproxy.exe .
```

## Why a Go sidecar?

The userspace WireGuard implementation (`wireguard-go`) and gVisor's netstack are both Go-only.
A pure-managed C# port would require porting the WireGuard transport handshake (Noise IK
variant, ChaCha20-Poly1305, Curve25519) and a full userspace TCP/IP stack. The sidecar approach
ships a 10 MB binary instead, with proven crypto and netstack.

## Mock mode

`{"mock": true}` skips WireGuard entirely and dials targets via the OS resolver/sockets. Used
by Wormhole's integration tests so CI doesn't need a real WG peer.
