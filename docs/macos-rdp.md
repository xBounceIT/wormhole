# RDP on macOS

The macOS DMG includes the SDL3 FreeRDP client for Intel and Apple Silicon.
Installing or updating Wormhole also installs this client inside the application;
Homebrew, XQuartz, and a separate Remote Desktop application are not required.
RDP opens in a separate native window, as before. Existing installations need a
release containing this change; changing the source does not update installed apps.

The Go backend first searches `freerdp/sdl-freerdp` beside its own executable, then
falls back to the existing system-client locations. `WORMHOLE_FREERDP_PATH` remains
an explicit override. Credentials still pass through stdin, and VPN routing and
tunnel leases remain managed by the existing backend.

## Building

Run `.github/actions/setup-macos-rdp/action.yml` on macOS, or prepare the vcpkg
revision from `tools/macos-freerdp/vcpkg.json` using a full clone (version overrides
require historical port trees), bootstrap it, and set
`WORMHOLE_RDP_VCPKG_ROOT` to that checkout. Install CMake, Ninja, and pkgconf on the
build machine, then run `npm run build:rdp:macos` before packaging.

The build pins FreeRDP 3.33.0 to its source commit, builds static dependencies for
both architectures, and merges the clients into a universal executable. It ships
SDL 3.4.18 explicitly: FreeRDP 3.33.0 incorrectly enables event names absent from
SDL 3.4.20. Keep this compatibility override until a newer FreeRDP build passes
the native CI checks with the newer SDL headers. The bundle includes
third-party license notices beside the client. The build and packaging checks
reject missing slices and any non-system dynamic library dependency. CI also
checks the ad-hoc signature and runs the relocated client without Homebrew on PATH.
Both CI and release builds exercise the actual bundled client's argument parser
with backend-generated stdin arguments, including gateway and certificate options.
The bundled build enables FreeRDP's legacy command-line compatibility for those
existing backend switches. This smoke test does not connect to an RDP server.

Builds reject a modified FreeRDP source checkout and take an exclusive build lock.
A failed rebuild removes the staged client and releases the lock so a retry is safe.
If the build process is forcibly terminated, remove
`obj/macos-freerdp-build.lock` only after confirming its owner PID has stopped.

This build uses SDL3 and native macOS audio/video support. Optional FFmpeg,
Kerberos, PKCS#11, USB redirection, and webview components are disabled. NLA with
username/password remains available. An explicit system-client override can be
used for deployments requiring additional FreeRDP components.

## Verification

`tests/macos-rdp-build.test.mjs` covers build orchestration, failures, architecture
checks, dependency rejection, and release integration. Go tests cover bundled
discovery priority and system fallback. Native compilation and the relocation
smoke test run in the macOS CI job; a real RDP server connection, authentication,
clipboard/audio, and VPN interoperability still require manual macOS testing.
