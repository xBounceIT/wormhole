# Wormhole Electron backend

This is the Go backend for the Electron migration shell. It owns SQLite access,
the Windows Credential Manager migration, DPAPI protection, and the workspace
metadata snapshot consumed by the TypeScript renderer.

The executable accepts:

```text
wormhole-backend-x64.exe --operation workspace --database <path>
wormhole-backend-x64.exe --operation migrate --database <path> --credential-reader <path>
wormhole-backend-x64.exe --operation auth-status --database <path>
wormhole-backend-x64.exe --operation auth-verify --database <path> < request.json
wormhole-backend-x64.exe --operation auth-set-secret --database <path> < request.json
wormhole-backend-x64.exe --operation auth-update-settings --database <path> < request.json
wormhole-backend-x64.exe --operation serve --database <path>
wormhole-backend-x64.exe --operation rdp --database <path> [--rdp-host <path>] [--freerdp <path>]
```

`migrate` is Windows-only and records
`windows-credential-manager-to-sqlite-v1` in `ElectronMigrations`. It copies
legacy values without deleting the Credential Manager source. `workspace` only
returns connection, credential, and tunnel metadata; it never returns secrets.

The `auth-*` operations own app authentication natively. They intentionally use
the same `%LOCALAPPDATA%\Wormhole\settings.json` fields and raw DPAPI document
(`app-auth.dpapi`, with `Wormhole.AppAuthentication.v1` entropy) as the WinUI
implementation, so an existing verifier works across both shells. Secrets are
accepted on stdin and never as command-line arguments.

`serve` keeps a Go-native JSON-lines backend process open for the Electron
renderer. It owns VNC connections, framebuffer decoding, pointer/key input,
and DPAPI-backed password lookup. Effective VPN-routed VNC targets fail closed
until the Electron tunnel providers are migrated; the backend never falls back
to direct TCP. Responses and events are written to stdout; diagnostic output
is kept off the protocol stream.

`rdp` is a long-lived JSON-lines supervisor. On Windows it launches the
packaged `wormhole-rdp-host-<arch>.exe` ActiveX host; on Linux and macOS it
launches `xfreerdp`/`xfreerdp3` (or the macOS `sdl-freerdp` clients). The
supervisor forwards sanitized lifecycle events but never emits the connection
profile or credential values back to Electron.
