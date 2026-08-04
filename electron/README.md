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

The renderer loads connection, credential, and tunnel metadata from the Go
backend over the Electron preload bridge. If the database is missing or empty,
the UI stays empty; it does not create demo connections or credentials. The
shell shape mirrors the current WinUI layout (title bar, update strip,
connection tree, footer navigation, session tabs, and protocol surface).

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
