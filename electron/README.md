# Wormhole Electron application

This directory contains the active Wormhole desktop shell. The React renderer
lives in `src/`, Electron owns native window and isolated Chromium lifecycle,
and all durable state and protocol behavior are delegated to the Go backend.
The former WinUI application has been removed; the Windows ActiveX RDP helper
under `tools/wormhole-rdp-host` remains part of the Electron runtime.

From the repository root:

```powershell
npm install
npm run dev
```

The default `npm run dev` command detects the host platform and architecture.
It always builds the Go backend and portable sidecars. On Windows it also
builds the native VPN sidecars, Credential Manager reader, and ActiveX RDP
host before Electron starts. The Windows path requires a real OpenVPN3 sidecar
and fails instead of accepting the development-only mock. The first run
automatically initializes the pinned OpenVPN3 and mbedTLS submodules; install
the toolchain documented in `tools/wormhole-ovpnproxy/README.md` before the
first run. `npm run dev:windows:arm64` remains available for an explicit ARM64
Windows build.

The renderer uses Vite 8, React, TypeScript 7, Shadcn/Radix components, Oxlint,
and Oxfmt. `npm run build` creates the static renderer in `dist/` and
the Electron process bundle in `dist-electron/`.

The generic `build` command compiles the Go backend for the current host
platform without the Windows-only helpers. Use `build:windows` when preparing
all Windows distributable inputs without starting the development app.

The renderer loads connection, credential, and tunnel metadata from the Go
backend over the Electron preload bridge. If the database is missing or empty,
the UI stays empty; it does not create demo connections or credentials. The
shell provides a title bar, update strip, connection tree, footer navigation,
session tabs, and protocol surfaces.

App authentication is available on every Electron platform. Go owns PIN and
password verification, startup/reload locking, confirmation prompts, and idle
locking. Windows uses the same DPAPI verifier document as WinUI; macOS and
Linux keep a per-workspace encryption key in the system keychain and use it to
protect the verifier document. Windows Hello remains Windows-only, uses the
Electron window as the native verification dialog owner, and always falls back
to the configured PIN or password elsewhere.

The Credentials page supports creating, editing, and deleting local password
profiles for SSH, RDP, and VNC. The password crosses only the isolated preload
bridge and Go writes the profile and secret reference together. Windows keeps
the DPAPI-protected `CredentialSecrets` format; macOS uses Keychain in a
cgo-enabled build; Linux uses the freedesktop Secret Service directly over
D-Bus, without requiring the optional `secret-tool` executable. There is
deliberately no plaintext fallback when the platform secret service is
unavailable; references written by older releases retain a compatibility reader.
SSH-key and Bitwarden-backed profiles are resolved by Go without exposing their
secrets to the renderer.

Saved SSH connections opened from the tree use a persistent Go backend process
over a JSON-lines stdio channel. The backend resolves inherited connection data,
decrypts migrated DPAPI secrets, and creates the PTY with Go's native
`golang.org/x/crypto/ssh` package. Go also owns the VT/ANSI terminal emulator;
the renderer receives only session metadata and validated terminal screen frames
plus bounded scrollback batches through the preload bridge. It never opens a
socket or reads Credential Manager / DPAPI data directly. Local saved passwords,
SSH keys, and Bitwarden-backed saved credentials are supported. Quick Connect supports
temporary password-authenticated SSH, HTTP(S), VNC, RDP, and serial sessions; network
sessions can select a saved VPN route, while serial remains local-only. Temporary SSH
connections accept an optional port and request username/password credentials without
saving them to the connection tree. For saved SSH connections, Go resolves inherited
VPN settings; when a route is enabled,
Electron starts the selected Go userspace sidecar and dials only through its loopback SOCKS5
endpoint. A failed tunnel never falls back to a direct SSH connection.

VNC sessions use the same bundled Go backend as a long-lived JSON-lines
process. The renderer sends connect, pointer, and key commands over the
preload bridge; the Go process owns the native RFB connection, framebuffer
decoding, and DPAPI-backed password lookup. Effective VNC routes use the same
Go VPN sidecars and SOCKS5 path as SSH. RDP uses a Go-owned loopback forwarder
over that SOCKS5 endpoint, so the native ActiveX/FreeRDP client never bypasses
the selected tunnel.

The Tunnels page creates, edits, tests, imports, and deletes encrypted tunnel records,
and folder/connection editors assign a route with inherit / off / selected
tunnel semantics. WireGuard, OpenVPN, Fortinet (password, embedded SAML, or system-browser
SAML), WatchGuard (password, imported profile, or SAML), Stormshield (automatic,
imported profile, and OTP), Azure VPN with Microsoft Entra ID, and Cisco Secure Client run
through native Go backends and bundled Go sidecars. Interactive challenges are serialized by
the Electron main process; browser tokens and VPN cookies stay inside isolated authentication
sessions and are handed directly to Go rather than exposed to the renderer. A failed provider
never falls back to routing outside the tunnel.

Saved HTTP and HTTPS connections use a native Electron Chromium surface, kept
separate from the React renderer. The Go backend resolves inherited web target
settings (including the leaf-only HTTPS certificate opt-in) before Electron
navigates it; connection tabs provide back, forward, and reload controls. A tunneled tab
uses an isolated Chromium session configured with the Go sidecar's loopback SOCKS5 proxy;
the Go web controller owns the ref-counted tunnel lease until that tab closes.
Normal tabs share only an in-memory Electron-run browser profile. A tab that
ignores certificate errors receives its own in-memory profile so that approval
cannot affect another connection. As with SSH and VNC, a failed VPN route never falls
back to the host network.

On the first Windows launch, the Electron main process copies legacy local
Wormhole passwords (saved profiles, inline connection passwords, and the MCP
token) from Windows Credential Manager into the existing
`%LOCALAPPDATA%\Wormhole\wormhole.db`. The Go backend protects copied values
with Windows DPAPI before writing `CredentialSecrets`. The completion marker
lives in `ElectronMigrations`; later launches do not read Credential Manager.
The source entries are intentionally retained so the migration is non-destructive.

Build the Windows Go backend and Credential Manager reader alongside the
Electron process before running the Windows app:

```powershell
npm run build:windows
```

Use `npm run build:windows:arm64` for an ARM64 build. The Windows-only helper
is included by the Windows build commands; Linux and macOS use the installed
FreeRDP client at runtime.

RDP follows the same split as the native client. Windows ships a separate
`wormhole-rdp-host-<arch>.exe` process that reuses the tested WinForms
`RdpHostForm`/mstscax ActiveX surface; the Go backend owns its lifecycle and
forwards secret-free status events to Electron. Linux and macOS launch the
installed `xfreerdp`, `xfreerdp3`, or macOS SDL FreeRDP client under Go
(`WORMHOLE_FREERDP_PATH` can override discovery). X11 Linux uses FreeRDP's
parent-window option to place the client in the Electron surface. macOS
FreeRDP builds are launched as their native client window because an X11
parent cannot be attached to an Electron Cocoa window.

The RDP credential prompt keeps credentials in memory for the current app
session only. Build the Windows ActiveX host directly with
`npm run build:rdp-host` or `npm run build:rdp-host:arm64` when iterating on
the native path.

The Go backend tests run with:

```powershell
Push-Location tools/wormhole-backend
go test ./...
Pop-Location
```
