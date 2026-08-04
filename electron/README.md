# Wormhole Electron migration shell

This directory contains the Electron main process. The React renderer lives in
`src/` so the new shell can sit beside the existing WinUI 3 implementation while
protocol providers are migrated incrementally.

From the repository root:

```powershell
npm install
npm run dev
```

The default `npm run dev` command detects the host platform and architecture.
On Windows it builds the Go backend and Credential Manager reader before
Electron starts; on other platforms it skips the Windows-only binaries.
`npm run dev:windows:arm64` remains available for an explicit ARM64 Windows
build.

The renderer uses Vite 8, React, TypeScript 7, Shadcn/Radix components, Oxlint,
and Oxfmt. `npm run build` creates the static renderer in `dist/` and
the Electron process bundle in `dist-electron/`.

The generic `dev` and `build` commands also compile the Go backend for the
current host platform. Windows adds the Credential Manager reader and native
ActiveX host through the `dev:windows` / `build:windows` commands.

The renderer loads connection, credential, and tunnel metadata from the Go
backend over the Electron preload bridge. If the database is missing or empty,
the UI stays empty; it does not create demo connections or credentials. The
shell shape mirrors the current WinUI layout (title bar, update strip,
connection tree, footer navigation, session tabs, and protocol surface).

Saved SSH connections opened from the tree use a persistent Go backend process
over a JSON-lines stdio channel. The backend resolves inherited connection data,
decrypts migrated DPAPI secrets, and creates the PTY with Go's native
`golang.org/x/crypto/ssh` package. The renderer receives only session metadata
and base64 terminal bytes through the preload bridge; it never opens a socket or
reads Credential Manager / DPAPI data directly. Local saved passwords and SSH
keys are supported; Bitwarden credentials, interactive credential prompts, and
Quick Connect are not wired in this migration slice. A connection configured
for a VPN tunnel is rejected until Electron tunnel routing is available rather
than falling back to a direct SSH connection.

VNC sessions use the same bundled Go backend as a long-lived JSON-lines
process. The renderer sends connect, pointer, and key commands over the
preload bridge; the Go process owns the native RFB connection, framebuffer
decoding, and DPAPI-backed password lookup. An effective VPN route currently
fails closed until the Electron Go tunnel providers are migrated; it is never
silently replaced with a direct TCP connection.

On the first Windows launch, the Electron main process copies legacy local
Wormhole passwords (saved profiles, inline connection passwords, and the MCP
token) from Windows Credential Manager into the existing
`%LOCALAPPDATA%\Wormhole\wormhole.db`. The Go backend protects copied values
with Windows DPAPI before writing `CredentialSecrets`. The completion marker
lives in `ElectronMigrations`; later launches do not read Credential Manager.
The source entries are intentionally retained while the WinUI and Electron
applications coexist.

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
