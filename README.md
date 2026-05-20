# Wormhole

A modern, tabbed, multi-protocol connection manager for Windows — a
philosophical sequel to [mRemoteNG](https://mremoteng.org).

> **Status:** 0.1.0 scaffold. The shell builds and runs; protocol surfaces (SSH, RDP, SFTP) ship in follow-up PRs.

## Why

mRemoteNG nailed something most remote clients still don't: a single window
with a **tree of saved servers**, folder-level inheritance for usernames /
ports / credentials, and tabs for every protocol. But its UI is stuck in 2010,
its last stable release is from 2019, and SFTP is a side feature, not a
first-class tab. Wormhole aims to keep what mRemoteNG got right and modernize
everything else.

## Goals (v0.1 MVP)

- Connection tree with folders, search, and drag-reorder.
- **Folder-level inheritance** — set a credential on a folder, every child inherits.
- Tabbed workspace.
- SSH terminal (xterm.js in WebView2, driven by SSH.NET).
- Embedded RDP session via the `mstscax` ActiveX control.
- SFTP dual-pane browser tab.
- DPAPI / Credential Manager-backed credential store.
- SQLite-backed connection store with a versioned schema.
- Modern WinUI 3 shell: Mica backdrop, dark mode, per-monitor DPI.

## v1 (planned)

- Import from mRemoteNG's `confCons.xml`.
- VNC and Telnet protocols.
- External Tools with `{host}` / `{user}` templating.
- Port scan → "add as connection."
- Windows Hello unlock, optional 1Password / Bitwarden / Azure Key Vault providers.
- SSH tunneling UI.
- Ctrl+K command palette.

## Requirements

- Windows 10 19041 (20H1) or later, on x64 or arm64.
- .NET 10 SDK to build.
- [WebView2 runtime](https://developer.microsoft.com/microsoft-edge/webview2/) (evergreen; installed by default on modern Windows).

## Build from source

```powershell
dotnet restore
dotnet build Wormhole.csproj -c Debug -p:Platform=x64
dotnet test  Wormhole.Tests/Wormhole.Tests.csproj
```

Then run `bin\x64\Debug\net10.0-windows10.0.19041.0\Wormhole.exe`.

## Stack

| Concern | Choice |
|---|---|
| UI framework | WinUI 3 (Windows App SDK 1.8.x) |
| MVVM | CommunityToolkit.Mvvm |
| DI | Microsoft.Extensions.DependencyInjection |
| Logging | Serilog → Microsoft.Extensions.Logging |
| SSH + SFTP | SSH.NET |
| Terminal renderer | xterm.js inside WebView2 |
| RDP | `mstscax` ActiveX (in-box) hosted via WinForms reparenting |
| Credentials | Meziantou.Framework.Win32.CredentialManager + DPAPI |
| Database | SQLite via Microsoft.Data.Sqlite + Dapper |

See [AGENTS.md](AGENTS.md) for architecture notes and conventions.

## License

TBD.
