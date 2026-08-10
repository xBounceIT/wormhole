# Wormhole

A modern, cross-platform, tabbed, multi-protocol connection manager inspired
by [mRemoteNG](https://mremoteng.org).

> Status: active development. The only product and release target is the
> Electron application. The former .NET 10 / WinUI 3 application has been
> removed from the repository.

## Architecture and development boundary

Wormhole is intentionally split into a thin frontend and a native backend:

- Frontend: React and TypeScript under src/. It renders application state,
  collects user input, and communicates through the preload bridge.
- Desktop shell: Electron code under electron/. It owns window lifecycle,
  isolated Chromium surfaces, and narrow, validated IPC.
- Backend: native, cross-platform Go under tools/. Go owns SQLite, migrations,
  secrets, app authentication, connection inheritance, protocols, sessions,
  VPNs, imports, logging, and updates.

In other words, all application behavior is implemented in native
cross-platform Go except for the frontend. Electron is the desktop shell and
bridge, not a second backend. New feature work must target Electron plus Go;
do not reintroduce the removed WinUI application.

The Go core is designed to run across supported Electron hosts. Unavoidable
operating-system integrations are isolated in Go platform adapters or narrowly
scoped native compatibility helpers; shared domain behavior remains in Go.

## What works today

- Saved connection trees with folders, search, drag-reorder, and folder-level
  inheritance for credentials, ports, connection settings, and VPN tunnels.
- Tabbed SSH, RDP, VNC, HTTP/HTTPS web, and Serial sessions.
- Go-owned SSH and serial terminal sessions with validated terminal frames and
  bounded scrollback delivered to the renderer.
- SFTP file transfer from connected SSH sessions.
- VNC connections with no-auth and classic password authentication.
- HTTP/HTTPS appliance sessions in isolated Electron Chromium surfaces.
- Native app authentication and protected credential storage owned by Go.
- Per-connection userspace VPN tunnels for WireGuard, OpenVPN, Fortinet,
  WatchGuard, Stormshield, Azure VPN, and Cisco Secure Client.
- Optional MCP server for controlling already-open SSH sessions.
- Optional Bitwarden integration for saved credential passwords and HTTPS
  browser autofill.
- Versioned SQLite storage and in-app update checks.
- Preview-before-commit mRemoteNG XML import for SSH, RDP, and VNC trees,
  including AES-GCM protected passwords, structure-only fallback, bounded
  parsing, collision-safe credential names, and atomic workspace writes.

## Per-connection VPN

VPN configurations are stored separately from connections and resolved through
the same folder-inheritance path. A connection can inherit a tunnel, select a
different tunnel, or explicitly disable tunneling.

Go owns tunnel configuration, protected payloads, provider selection, ref-counted
leases, and fail-closed routing. Native Go sidecars expose loopback SOCKS5
endpoints or local forwarders to the session implementations. A failed tunnel
never silently falls back to a direct connection.

The providers are:

- WireGuard
- OpenVPN
- Fortinet SSL VPN, including supported SAML flows
- WatchGuard Mobile VPN with SSL
- Stormshield Network SSL VPN
- Azure VPN with Microsoft Entra ID
- Cisco Secure Client / AnyConnect

SSH, SFTP, VNC, RDP, and HTTP/HTTPS sessions use the tunnel selected by the
effective inherited profile. Serial sessions are local COM-port sessions and
do not use VPN routing.

## AI agent control

Wormhole includes an opt-in
[Model Context Protocol](https://modelcontextprotocol.io) server for already-open
SSH sessions. It is loopback-only and protected by a bearer token owned by the
Go backend. The available operations are intentionally limited to listing
sessions, running commands, sending text, and reading recent terminal output.
It cannot open connections or read saved credentials.

## Requirements

Electron and Go are the primary application runtimes:

- Node.js and npm.
- Go 1.25 or newer, matching tools/wormhole-backend/go.mod.
- The Electron runtime downloaded by npm for the desktop shell.
- The .NET 10 SDK on Windows, only for the separate ActiveX RDP host used by
  Electron.
- Platform-native dependencies only where a particular protocol client or OS
  integration requires them.

## Build and test

Install dependencies from the repository root:

    npm install

Run the development app:

    npm run dev

Build the renderer, Electron process, and current-host Go backend:

    npm run build

Run the complete Electron, Go, and helper test suite:

    npm run test:electron

Useful focused checks:

    npm run typecheck
    npm run lint
    npm run format:check
    npm run test:rdp-host

The Go backend can also be tested directly:

    Set-Location tools/wormhole-backend
    go test ./...

Windows packaging builds the Go backend and required native integration
artifacts:

    npm run build:windows
    npm run build:windows:arm64
    npm run build:installer
    npm run build:installer:arm64

The Electron application is the only release workflow. Linux releases publish
a portable AppImage plus installable DEB and RPM packages for x86-64 and ARM64.
Windows releases publish the installer and portable ZIP, while macOS releases
publish the DMG.

## Stack

| Concern | Choice |
|---|---|
| Frontend | React, TypeScript, Vite |
| Desktop shell | Electron |
| Backend | Native cross-platform Go |
| Persistence | SQLite through modernc.org/sqlite |
| Terminal and sessions | Go-native protocol/session services |
| VPN tunnels | Go providers and native Go sidecars |
| Secrets and authentication | Go-owned OS protection and encrypted stores |
| IPC | Validated Electron preload bridge and Go process protocols |
| Import | Go-owned, preview-before-commit mRemoteNG XML importer |
| AI control | Go-owned loopback MCP server |

See [electron/README.md](electron/README.md) for Electron-specific details and
[tools/wormhole-backend/README.md](tools/wormhole-backend/README.md) for the
backend operations and process contracts.

## License

Wormhole is licensed under the **GNU Affero General Public License v3.0 or later**
(AGPL-3.0-or-later). See [LICENSE](LICENSE) for the full text.

Third-party dependencies and their licenses are documented in
[THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md).
