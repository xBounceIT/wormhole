<!-- AGENTS.md mirrors this file (this is the canonical copy). When updating one, update both. -->

# Wormhole — Agent guide

## Product direction

Wormhole is developed and shipped only as the Electron application. The former
.NET 10 / WinUI 3 application has been removed. The only managed component is
the Windows ActiveX RDP host under tools/, a narrow helper used by Electron.

The active architecture has a strict boundary:

- Frontend: React and TypeScript under src/. It renders state, collects user
  input, and talks to the application only through the preload bridge.
- Desktop shell: Electron main and preload code under electron/. It owns window
  lifecycle, isolated Chromium surfaces, and narrow, validated IPC.
- Backend: native, cross-platform Go under tools/. Go owns the application
  domain and every backend function: SQLite, migrations, secrets, app
  authentication, protocols, sessions, VPNs, imports, logging, and updates.

All new feature work belongs to Electron plus Go. Do not add backend behavior
to React, TypeScript, Node.js, Electron main-process code, or the managed RDP
helper. Platform-specific adapters belong at the Go boundary and must not move
domain logic into the frontend.

## Daily workflow

- Install dependencies: npm install
- Run the development app: npm run dev
- Build the renderer, Electron process, and current-host Go backend: npm run build
- Build the Windows distributable inputs: npm run build:windows
- Build Windows ARM64 inputs: npm run build:windows:arm64
- Build the Windows installer: npm run build:installer or npm run build:installer:arm64
- Run the Electron, Go, and helper test suites: npm run test:electron
- Run TypeScript checks: npm run typecheck
- Run lint and formatting checks: npm run lint and npm run format:check
- Run backend tests directly when iterating: Set-Location
  tools/wormhole-backend, then run go test ./...

.NET is used only to build and test the Windows RDP helper with
npm run build:rdp-host and npm run test:rdp-host. There is no root .NET solution
or WinUI validation workflow.

## Engineering rules

- Keep the renderer presentation-focused. It must not open sockets, read
  SQLite, access the filesystem, handle credentials, or implement protocol
  behavior directly.
- Keep the Electron main/preload layer thin. Validate IPC inputs and outputs,
  delegate durable state and domain decisions to Go, and never duplicate Go
  business rules in TypeScript.
- Use Go as the source of truth for persistence, migrations, authentication,
  secrets, connection profiles, inheritance, sessions, tunnels, updates, and
  imports.
- Keep the Go core cross-platform. Put unavoidable operating-system code in
  clearly scoped platform files or adapters; shared behavior remains in common
  Go code. Do not assume Windows paths, APIs, or credential stores in common
  code.
- Treat JSON-lines/stdin/stdout process protocols as machine interfaces:
  stdout is protocol data, stderr is diagnostics, and messages must be bounded
  and validated.
- Never put passwords, tokens, private keys, tunnel payloads, or auth cookies
  in logs, command-line arguments, renderer state, or unencrypted files.
  Secrets are accepted through Go-owned protected stores or stdin and must be
  redacted before logging.
- Go owns network and terminal work. The renderer receives validated state,
  terminal frames, and bounded scrollback rather than raw credentials or
  unrestricted sockets.
- Preserve fail-closed VPN behavior. A tunnel failure must never silently fall
  back to a direct connection.
- Add focused Go tests for backend behavior and TypeScript tests for pure
  renderer/bridge state. Run npm run test:electron before handing off changes.

## Active architecture

- The workspace and settings data live in SQLite managed by Go. Schema changes
  are versioned migrations applied by the Go backend.
- Go resolves inherited connection and tunnel profiles, owns credential and
  app-auth verification, and exposes only the minimum metadata needed by the
  renderer.
- SSH, serial, VNC, RDP routing, web targets, SFTP, MCP, and update operations
  are backend responsibilities. Electron provides lifecycle and rendering
  integration only.
- VPN providers run through Go-native sidecars and loopback SOCKS5 or forwarder
  endpoints. Session code must hold and release tunnel leases deterministically.
- Electron web sessions use isolated Chromium profiles. Authentication tokens
  and VPN cookies stay in the owning native/auth flow and are never exposed to
  React.
- Windows-only native compatibility helpers may remain where an operating
  system client requires them, but they are adapters behind the Go-owned
  boundary, not a second application architecture. New behavior must still be
  implemented in Go.

## Packaging and repository hygiene

- The Electron installer is the only release target. Use the Electron build and
  installer scripts under scripts/; do not add a parallel desktop shell or
  release workflow.
- Keep Windows x64 and arm64 packaging working, while preserving the
  cross-platform Go build for other supported Electron hosts.
- Do not switch the app to MSIX or reintroduce WinUI as the active shell.
- Preserve existing user changes in a dirty worktree. Inspect git status before
  editing and avoid destructive reset or checkout commands.
- When updating this guide, update the mirrored agent guide in the same change
  so the instructions remain identical.

## Native compatibility helpers

The C# code under tools/wormhole-rdp-host is part of the Electron application:
it hosts the Windows mstscax ActiveX control in a separate process. Keep it
isolated, secret-free, and limited to native surface integration. Do not
reintroduce the removed WinUI application or move backend behavior into it.
