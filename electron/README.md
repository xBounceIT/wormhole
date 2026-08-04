# Wormhole Electron migration shell

This directory contains the Electron main process. The React renderer lives in
`src/` so the new shell can sit beside the existing WinUI 3 implementation while
protocol providers are migrated incrementally.

From the repository root:

```powershell
npm install
npm run dev
```

On Windows, use `npm run dev:windows` so the Go backend and Credential Manager
reader are built before Electron starts.
On ARM64 Windows, use `npm run dev:windows:arm64` instead.

The renderer uses Vite 8, React, TypeScript 7, Shadcn/Radix components, Oxlint,
and Oxfmt. `npm run build` creates the static renderer in `dist/` and
the Electron process bundle in `dist-electron/`.

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

Use `npm run build:windows:arm64` for an ARM64 build. The cross-platform
`npm run build` command intentionally builds only the renderer and Electron
bundle; the Windows-only helper is included by the Windows build commands.

The Go backend tests run with:

```powershell
Push-Location tools/wormhole-backend
go test ./...
Pop-Location
```
