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
