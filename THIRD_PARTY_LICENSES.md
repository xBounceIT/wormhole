# Third-party licenses

Wormhole itself is licensed under **AGPL-3.0-or-later** (see [LICENSE](LICENSE)).
This document inventories the third-party software it depends on, with
the license of each. Component-name links go to the upstream project; the
license-name links point at the canonical license text where available.

## Vendored as source / submodules

Vendored components ship as source under `tools/wormhole-ovpnproxy/third_party/`.
Each subdirectory contains the upstream's own LICENSE file unmodified.

| Component | Version pin | License | Where |
| --- | --- | --- | --- |
| [openvpn3](https://github.com/OpenVPN/openvpn3) | git submodule | [AGPL-3.0](https://www.gnu.org/licenses/agpl-3.0.txt) (with commercial dual-license available from OpenVPN Inc.) | `tools/wormhole-ovpnproxy/third_party/openvpn3/` |
| [mbedtls](https://github.com/Mbed-TLS/mbedtls) | git submodule | [Apache-2.0](https://www.apache.org/licenses/LICENSE-2.0) | `tools/wormhole-ovpnproxy/third_party/mbedtls/` |

The AGPL license of openvpn3 is the reason Wormhole itself is AGPL — linking
AGPL code into a project requires the project be AGPL-compatible. If you do
not want this constraint and have a use case requiring a more permissive
license, OpenVPN Inc. offers commercial licensing at <https://openvpn.net/>.

## Go modules (sidecar binaries)

Used by `tools/wormhole-wgproxy` and `tools/wormhole-ovpnproxy`.

| Module | License |
| --- | --- |
| [`golang.zx2c4.com/wireguard`](https://git.zx2c4.com/wireguard-go) (wireguard-go) | [MIT](https://git.zx2c4.com/wireguard-go/tree/COPYING) |
| [`golang.zx2c4.com/wintun`](https://git.zx2c4.com/wintun) | MIT (per `golang.zx2c4.com/wintun` package metadata; transitive only — Wormhole does not load the Wintun driver) |
| [`gvisor.dev/gvisor`](https://gvisor.dev/) (netstack) | [Apache-2.0](https://github.com/google/gvisor/blob/master/LICENSE) |
| [`golang.org/x/crypto`](https://pkg.go.dev/golang.org/x/crypto), [`x/net`](https://pkg.go.dev/golang.org/x/net), [`x/sys`](https://pkg.go.dev/golang.org/x/sys), [`x/time`](https://pkg.go.dev/golang.org/x/time) | [BSD-3-Clause](https://cs.opensource.google/go/x/crypto/+/master:LICENSE) |
| [`github.com/google/btree`](https://github.com/google/btree) | [Apache-2.0](https://github.com/google/btree/blob/master/LICENSE) |

## NuGet packages (managed side)

Used by `Wormhole.csproj`.

| Package | License |
| --- | --- |
| [Microsoft.WindowsAppSDK](https://learn.microsoft.com/windows/apps/windows-app-sdk/) | MIT (with proprietary Windows runtime components — see [the SDK license](https://learn.microsoft.com/windows/apps/windows-app-sdk/license)) |
| [Microsoft.Web.WebView2](https://learn.microsoft.com/microsoft-edge/webview2/) | Proprietary Microsoft SDK license — see package terms |
| [CommunityToolkit.Mvvm](https://github.com/CommunityToolkit/dotnet) | MIT |
| Microsoft.Extensions.DependencyInjection / Http / Logging / Logging.Abstractions (provided by the .NET / ASP.NET Core shared framework) | MIT |
| [Microsoft.AspNetCore.App](https://github.com/dotnet/aspnetcore) & [Microsoft.WindowsDesktop.App.WindowsForms](https://github.com/dotnet/winforms) (.NET shared frameworks — Kestrel hosts the in-app MCP server; WinForms hosts the RDP ActiveX) | MIT |
| [Serilog](https://github.com/serilog/serilog), Serilog.Sinks.File, Serilog.Extensions.Logging | Apache-2.0 |
| [SSH.NET](https://github.com/sshnet/SSH.NET) | MIT |
| [ModelContextProtocol.AspNetCore](https://github.com/modelcontextprotocol/csharp-sdk) | Apache-2.0 (the package 1.3.0 declares Apache-2.0; the SDK is transitioning from MIT) |
| [Meziantou.Framework.Win32.CredentialManager](https://github.com/meziantou/Meziantou.Framework) | MIT |
| [Microsoft.Data.Sqlite](https://learn.microsoft.com/dotnet/standard/data/sqlite/) | MIT (bundles the [SQLite library](https://www.sqlite.org/copyright.html), public domain) |
| [Dapper](https://github.com/DapperLib/Dapper) | Apache-2.0 |
| [BouncyCastle.Cryptography](https://github.com/bcgit/bc-csharp) | MIT (based on the MIT X Consortium license; bundles a modified Bzip2 under Apache-2.0) |
| [xunit](https://github.com/xunit/xunit) (test-only) | Apache-2.0 |

## Web assets

xterm.js (`Assets/web/`) is loaded into the SSH terminal's WebView2.

| Component | License |
| --- | --- |
| [xterm.js](https://github.com/xtermjs/xterm.js) | MIT |

## How attribution works at distribution

A Wormhole release zip ships:
- `LICENSE` (AGPL-3.0 text for Wormhole itself)
- `THIRD_PARTY_LICENSES.md` (this file)
- Inside `tools/wormhole-ovpnproxy/third_party/<component>/LICENSE` for each
  vendored source dependency

If you build the Inno Setup installer (`scripts/Build-Installer.ps1`), the
installer bundle includes all of the above. If you `git clone` Wormhole for
development, `git submodule update --init` pulls the vendored components and
their license files alongside the source.

## Updating this file

When adding or removing a dependency:
1. Update this file.
2. If the new dependency is GPL-incompatible (proprietary, BSD-without-
   advertising-clause is fine, anything stricter than AGPL is not), stop
   and reconsider — AGPL-3.0 cannot link against proprietary code without
   permission.
3. If the new dependency itself adds a copyleft requirement stricter than
   AGPL-3.0, Wormhole's own license must rise to that level (e.g. GPLv3
   "or later" → no change; GPLv3 only → conflict, must upgrade Wormhole).
