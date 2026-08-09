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

Used by the Go sidecar binaries, including `tools/wormhole-backend`,
`tools/wormhole-wgproxy`, and `tools/wormhole-ovpnproxy`.

| Module | License |
| --- | --- |
| [`golang.zx2c4.com/wireguard`](https://git.zx2c4.com/wireguard-go) (wireguard-go) | [MIT](https://git.zx2c4.com/wireguard-go/tree/COPYING) |
| [`golang.zx2c4.com/wintun`](https://git.zx2c4.com/wintun) | MIT (per `golang.zx2c4.com/wintun` package metadata; transitive only — Wormhole does not load the Wintun driver) |
| [`gvisor.dev/gvisor`](https://gvisor.dev/) (netstack) | [Apache-2.0](https://github.com/google/gvisor/blob/master/LICENSE) |
| [`golang.org/x/crypto`](https://pkg.go.dev/golang.org/x/crypto), [`x/net`](https://pkg.go.dev/golang.org/x/net), [`x/sys`](https://pkg.go.dev/golang.org/x/sys), [`x/time`](https://pkg.go.dev/golang.org/x/time) | [BSD-3-Clause](https://cs.opensource.google/go/x/crypto/+/master:LICENSE) |
| [`github.com/google/btree`](https://github.com/google/btree) | [Apache-2.0](https://github.com/google/btree/blob/master/LICENSE) |
| [`github.com/zalando/go-keyring`](https://github.com/zalando/go-keyring) | [MIT](https://github.com/zalando/go-keyring/blob/master/LICENSE) |
| [`github.com/godbus/dbus/v5`](https://github.com/godbus/dbus) | [BSD-2-Clause](https://github.com/godbus/dbus/blob/master/LICENSE) |
| [`github.com/danieljoos/wincred`](https://github.com/danieljoos/wincred) | [MIT](https://github.com/danieljoos/wincred/blob/master/LICENSE) |

## Managed Windows helper

The Electron-only Windows RDP helper under `tools/wormhole-rdp-host` uses the
.NET shared frameworks and does not reference third-party NuGet packages.

| Component | License |
| --- | --- |
| [Microsoft.WindowsDesktop.App.WindowsForms](https://github.com/dotnet/winforms) | MIT |

Test-only managed dependencies, not included in release artifacts:

| Package | License |
| --- | --- |
| [Microsoft.NET.Test.Sdk](https://github.com/microsoft/vstest) | MIT |
| [xUnit.net](https://github.com/xunit/xunit) | Apache-2.0 |

## How attribution works at distribution

A Wormhole release zip ships:
- `LICENSE` (AGPL-3.0 text for Wormhole itself)
- `THIRD_PARTY_LICENSES.md` (this file)
- Inside `tools/wormhole-ovpnproxy/third_party/<component>/LICENSE` for each
  vendored source dependency

The Electron installer built by `scripts/Build-ElectronInstaller.ps1` includes
the release license files. If you `git clone` Wormhole for development,
`git submodule update --init` pulls the vendored components and their license
files alongside the source.

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
