# Wormhole Electron backend

This is the Go backend for the Electron migration shell. It owns SQLite access,
the Windows Credential Manager migration, DPAPI protection, and the workspace
metadata snapshot consumed by the TypeScript renderer.

The executable accepts:

```text
wormhole-backend-x64.exe --operation workspace --database <path>
wormhole-backend-x64.exe --operation migrate --database <path> --credential-reader <path>
```

`migrate` is Windows-only and records
`windows-credential-manager-to-sqlite-v1` in `ElectronMigrations`. It copies
legacy values without deleting the Credential Manager source. `workspace` only
returns connection, credential, and tunnel metadata; it never returns secrets.
