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

#### macOS (Intel, Apple Silicon, universal)

Install the Xcode command-line tools, Go, CMake, Ninja, and a bootstrapped
[vcpkg checkout](https://github.com/microsoft/vcpkg), then set `VCPKG_ROOT` to
that checkout. Run `npm run build:backend` for the host architecture or
`npm run build:backend:universal` for both slices. Missing OpenVPN3 and mbedTLS
submodules are initialized automatically. CI and releases provision the same
pinned toolchain through `.github/actions/setup-macos-ovpn`.

The builder applies the same required patches as Windows, builds static
dependencies independently for `x64-osx` and `arm64-osx`, and links with Apple's
libc++ and system frameworks. It rejects missing sources, mock-only binaries,
incorrect Mach-O architectures, and non-system dynamic libraries. A local smoke
test exercises the native profile parser without connecting to a VPN. The
universal builder then verifies both architecture slices with `lipo`.

Overlapping OpenVPN builds in one checkout are rejected before changing shared
sources. Temporary binaries stay under `obj/macos-ovpn-build.lock`, outside the
packaged resources. Normal completion and failures remove the lock. After a hard
interruption, check the PID in `owner-pid` and confirm that build has stopped
before removing the lock directory and retrying. Development cache keys include
the vcpkg checkout, installed native dependencies, archives, and selected compilers.

`node --test tests/macos-ovpn-build.test.mjs` covers build orchestration and
failure cleanup on every host. Run it with Node's `--experimental-test-coverage`
and `--test-coverage-include=scripts/build-macos-ovpnproxy.mjs` to measure the
builder. CMake/CGO declarations and the process entrypoint are covered by
contract tests and the native macOS CI build rather than JavaScript coverage.
An actual Stormshield/OpenVPN/WatchGuard login still requires a live appliance.

#### Windows

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
3. **Git access to the OpenVPN3 + mbedTLS submodules**. When a real sidecar is
   required, the build script synchronizes both submodules (including populated
   checkouts) to the repository's pinned revisions, recursively. This prevents
   stale headers after a pull from breaking required patches. Git preserves local
   edits and stops the build if they conflict with the update; no forced checkout
   is used. The checkout strategy overrides local `submodule.update` policies
   (`none`, `merge`, `rebase`). Missing Git stops a required real build and removes
   a stale staged sidecar.

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

## OpenVPN3 compatibility patches

`Fetch-OvpnProxy.ps1` applies the files in `patches/` before compiling and restores
the submodule afterward. OpenVPN3 3.11.8 removes the incorrect extended-key-usage
fallback upstream, so the former OID include backport is no longer required.
The hostname, CBC padding, and dynamic tls-crypt exporter patches remain required.

The shim links its pinned mbedTLS 3.6.7 target directly, avoiding discovery of a
different system TLS library through pkg-config. Its factory explicitly declines
epoch data to preserve the existing DATA_V2 negotiation until provider integration
coverage is available.

Run `node --test tests/ovpn-mbedtls-compat.test.mjs` to compile the current upstream
header with both include orders and check distinct KU/EKU masks for mbedTLS 2.x/3.6.
The same suite exercises the new virtual factory capability and measures its line
coverage with GCC/gcov when available. These tests also run in `npm run test:packaging`.
On Windows it runs the production PowerShell bootstrap against local Git submodule
fixtures: stale and empty checkouts, repeated runs with local edits, conflicting
updates and missing Git that remove stale binaries, local update policies, and
optional builds that skip synchronization.
PowerShell is excluded from the project's Node/V8 coverage percentage because V8
cannot instrument it; these integration cases exercise both outcomes of the
changed `RequireReal` guard and its error path.
Native compile scenarios require a GCC/Clang-compatible C++ compiler (`CXX`, or
`g++` on Windows / `c++` elsewhere) and skip when it is unavailable.

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
  the shim's `ovpn_get_dns`) — never the OS resolver. Stormshield enables
  `public_dns_fallback`: if pushed DNS is absent or cannot resolve a public name,
  Cloudflare and Google DNS are tried through the same VPN netstack, using the
  tunnel's supported IP family. Pushed DNS answers retain priority, including
  private answers for public domains. Single-label names, private suffixes and
  reverse zones, `.onion` and malformed names never use the public fallback. The
  public DNS client reads no host files or system resolver settings and performs
  no OS route probes. It validates response IDs, questions and answer ownership,
  retries truncated UDP answers over TCP, and closes sockets on cancellation.
  Other OpenVPN providers keep the
  pushed-DNS-only policy and fail closed when DNS is missing.

  Pushed DNS gets up to four seconds before fallback; each public resolver gets
  two seconds, leaving time for the resource connection within the SOCKS timeout.
  If DNS returns several CDN addresses, connection attempts start 250 ms apart
  across distinct addresses of the tunnel's supported IP family. Each attempt
  retains the caller's remaining SOCKS timeout; later reachable edges are not
  starved by earlier unresponsive edges. Immediate failures advance without
  waiting when no other attempt remains active. Selecting a connection cancels
  pending attempts and closes any other successful connections.
  The VPN gateway must permit reaching the public DNS servers and resource hosts.
  No query or resource connection falls back to the host network on tunnel failure.

Run `go test ./... -coverprofile=coverage.out` in this module to verify DNS policy,
IPv4/IPv6 fallback, cancellation, CDN address retries and tunnel failure. DNS and
address selection are compiled in the normal test build; CGO setup only binds
them to the production netstack. Stormshield login and page loading still require
a live appliance.

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
