# wormhole-ovpnproxy

Userspace OpenVPN sidecar for Wormhole. Brings up an OpenVPN3-core client entirely in
user space (no TUN/Wintun driver, no admin rights, no OS-level effects) and exposes the
resulting virtual network through a local SOCKS5 listener on `127.0.0.1`. Pairs with
`wormhole-wgproxy` — the protocol surface is identical so the C# side can treat both
tunnel kinds uniformly through `OpenVpnProcessHost` / `WireGuardProcessHost`.

## Wire protocol

- **stdin**: one JSON object on the first line, then EOF acts as the shutdown signal.
- **stdout**: a single line `READY <port>\n` once the SOCKS5 listener is up AND the
  OpenVPN session is in the CONNECTED state.
- **stderr**: structured log lines (one per event, free-form text).

### stdin schema

```json
{
  "profile_ovpn": "client\nproto udp\nremote vpn.example.com 1194\n<ca>...</ca>\n...",
  "username": "alice",
  "password": "s3cret",
  "mock": false
}
```

`profile_ovpn` is the unmodified `.ovpn` blob — OpenVPN3 parses every directive (cipher
negotiation, TLS control channel, `tls-auth`, `tls-crypt`, `push-reply`, MTU, reneg,
replay). One exception: a profile with no inline client cert/key gets `setenv CLIENT_CERT 0`
appended, because OpenVPN3 otherwise treats it as an external-PKI profile and aborts with
"Missing External PKI alias" (the shim implements no external PKI). `username` / `password`
are passed to OpenVPN3 via `ProvideCreds` when either is non-empty. `mock: true`
short-circuits to an OS-socket dialer for tests.

## Building

Two variants — pick by build tag.

### Default (no OpenVPN3 link)

```
cd tools/wormhole-ovpnproxy
go build -trimpath -ldflags "-s -w" -o ../../bin/wormhole-ovpnproxy.exe .
```

The resulting binary supports `--mock` mode and the SOCKS5 wire protocol but real-mode
`startOpenVpn` returns an "OpenVPN3 binding not linked" error. Sufficient for CI / wire
contract tests.

### Production (`-tags ovpn3`)

Toolchain prerequisites (Windows, x64):

1. **C++17 toolchain** — one of:
   - MSYS2 + MinGW-w64: `pacman -S mingw-w64-ucrt-x86_64-gcc mingw-w64-ucrt-x86_64-cmake`
   - Visual Studio 2022 Build Tools (Desktop C++ workload) + `cmake`
   - Chocolatey: `choco install mingw cmake`
2. **vcpkg** (recommended for transitive C++ deps):
   ```powershell
   git clone https://github.com/microsoft/vcpkg C:\vcpkg
   C:\vcpkg\bootstrap-vcpkg.bat
   [Environment]::SetEnvironmentVariable("VCPKG_ROOT", "C:\vcpkg", "User")
   ```
3. **OpenVPN3 + mbedTLS submodules** (pinned in this repo):
   ```powershell
   git submodule update --init --recursive
   ```

Then build:

```powershell
# Fetch-OvpnProxy.ps1 detects VCPKG_ROOT + cmake + go automatically and runs the
# full build with -tags ovpn3. The first run takes ~10-15 min as vcpkg downloads
# and builds asio, jsoncpp, lz4, xxhash. Subsequent builds are incremental.
.\scripts\Fetch-OvpnProxy.ps1 -Arch x64 -Force -RequireReal
```

Or invoke the steps manually:

```powershell
# Build the C++ shim
cmake -B tools\wormhole-ovpnproxy\ovpn_shim\build\x64 `
      -S tools\wormhole-ovpnproxy\ovpn_shim `
      -G "MinGW Makefiles" `
      -DCMAKE_TOOLCHAIN_FILE=$env:VCPKG_ROOT\scripts\buildsystems\vcpkg.cmake `
      -DVCPKG_TARGET_TRIPLET=x64-mingw-static
cmake --build tools\wormhole-ovpnproxy\ovpn_shim\build\x64 --config Release

# Build the Go sidecar with the CGO link
cd tools\wormhole-ovpnproxy
$env:CGO_ENABLED = "1"
go build -trimpath -tags ovpn3 -ldflags "-s -w" -o ..\..\bin\wormhole-ovpnproxy.exe .
```

Cross-build for arm64 with an x64-hosted llvm-mingw archive (required because the
ARM64 sidecar links libc++ explicitly):

```powershell
$env:PATH = "C:\llvm-mingw\bin;$env:PATH"
.\scripts\Fetch-OvpnProxy.ps1 -Arch arm64 -Force -RequireReal
```

## Why a Go sidecar?

The gVisor netstack used to expose a userspace TUN to the SOCKS5 surface is Go-only.
OpenVPN3-core is C++ — we wrap it via CGO through a thin shim (`ovpn_shim/shim.cc`) that
implements OpenVPN3's `TunBuilderBase` over thread-safe packet queues. The shim's C ABI
keeps the CGO surface small (8 entry points) and lets us swap in a different VPN engine
later without touching the Go side.

## Mock mode

`{"mock": true}` or `--mock` skips OpenVPN entirely and dials targets via the OS
resolver/sockets. Used by Wormhole's integration tests so CI doesn't need a real OpenVPN
server.

## Why no OS network is touched

- No TAP / TUN driver installed: `tun_builder_establish` returns a synthetic handle and
  packets flow through the shim's internal `std::deque`.
- No Wintun adapter: gVisor's `channel.Endpoint` is purely in-process memory.
- No routing table changes: OpenVPN3's `tun_builder_add_route` is a no-op — the gVisor
  netstack already routes all traffic to NIC 1 inside this process.
- No DNS changes: hostnames are resolved through the tunnel via `tnet.LookupContextHost`
  against the server-pushed resolvers (`dhcp-option DNS` / `--dns server`, surfaced by
  the shim's `ovpn_get_dns`) — never the OS resolver. If the server pushes no DNS,
  hostname dials fail with a clear error rather than leaking lookups to the local
  network.

`ipconfig /all` is unchanged after a session starts. A diff of `netstat -anob` shows
exactly one new entry: this binary's SOCKS5 listener on a loopback port.

## Implementation notes

The shim uses OpenVPN3's `OPENVPN_EXTERNAL_TUN_FACTORY` compile-time hook to install
a custom `TunClient` on the OpenVPN3 core. This is the documented embedder extension
point for userspace bidirectional TUN (the same hook iOS / Android wouldn't use
because they receive a real TUN fd, but desktop embedders without an OS TUN device
exist exactly for this case):

- Server → client (decrypted in): the core calls our `TunClient::tun_send(buf)`
  which copies the packet into an inbound queue. Go drains via `ovpn_tun_recv`.
- Client → server (plain IP injected for encryption): Go calls `ovpn_tun_send`,
  the shim copies the buffer (Go GC can move the slice after the call returns),
  posts onto the OpenVPN3 `io_context` thread, and calls `parent_.tun_recv(buf)`.
  The core encrypts and hands it to the transport for delivery to the server.

## Known v1 limitations

- **Dual-stack IPv4 + IPv6 push.** The shim parses both `ifconfig` and
  `ifconfig-ipv6` push directives. `ovpn_wait_connected` currently surfaces only
  the v4 CIDR if both are present (v6 fallback when v4 is missing). A v2 ABI
  extension can fetch the full pair.
- **Dynamic challenge / 2FA, smartcard / PKCS#11, Windows certificate store.**
  Cert + username/password + TLS-auth/TLS-crypt work in v1; anything that
  requires interactive callback-style auth is deferred.
