# Wormhole — Agent guide

Wormhole is a .NET 10 / WinUI 3 Windows desktop app: a tabbed multi-protocol
connection manager (SSH, RDP, SFTP) positioned as a philosophical sequel to
mRemoteNG. This file orients agents touching the codebase.

## Daily workflow

- Build: `dotnet build Wormhole.csproj -c Debug -p:Platform=x64`
- Run tests: `dotnet test Wormhole.Tests/Wormhole.Tests.csproj`
- Run the app: build, then launch the produced `Wormhole.exe` from `bin\x64\Debug\net10.0-windows10.0.19041.0\`.
- Releases (later): `scripts/Build-Installer.ps1` produces an Inno Setup `.exe`.

## Conventions

- Respect WinUI 3 guidelines. Custom title bar, Mica backdrop, per-monitor DPI.
- DI: `Microsoft.Extensions.DependencyInjection` configured in [App.xaml.cs](App.xaml.cs). Resolve from `App.Current.Services`.
- MVVM: `CommunityToolkit.Mvvm` (`ObservableObject`, `[ObservableProperty]`, `[RelayCommand]`). View models live under [ViewModels/](ViewModels).
- Logging: log via `ILogger<T>` from MEL. Serilog is the provider. Logs land in `%LOCALAPPDATA%\Wormhole\logs\`.
- Persistence: SQLite via `Microsoft.Data.Sqlite` + Dapper at `%LOCALAPPDATA%\Wormhole\wormhole.db`. Schema is versioned by `.sql` files in [Data/Migrations/](Data/Migrations) (embedded resources), applied in alphabetical order by [Data/MigrationRunner.cs](Data/MigrationRunner.cs) at startup. Tracking table: `__migration_history`. To add a migration, drop a new `NNNN_description.sql` in that folder. Open connections via `ISqliteConnectionFactory.Open()` — one connection per operation (Microsoft.Data.Sqlite pools).
- Secrets:
  - **Passwords** → Windows Credential Manager via `Meziantou.Framework.Win32.CredentialManager` (key = `Wormhole:<credId>`). 2560-byte limit.
  - **Private keys** → DPAPI-encrypted files under `%LOCALAPPDATA%\Wormhole\keys\` (Credential Manager is too small).
  - **Never** log credentials. Add a redaction enricher before adding new logging around auth.

## Architecture pillars (the parts to handle with care)

- **Folder-level inheritance** (`Data/InheritanceResolver.cs`) is the load-bearing domain concept. It is the single thing that makes Wormhole feel like mRemoteNG. Always run its tests before touching it.
- **RDP host** must be on STA. The ActiveX `AxMsRdpClient9NotSafeForScripting` lives in a WinForms `Form` reparented into a WinUI 3 placeholder via Win32 `SetParent`. See [Interop/Rdp/RdpHostForm.cs](Interop/Rdp/RdpHostForm.cs).
- **SSH terminal** is xterm.js inside a `WebView2` bridged to SSH.NET `ShellStream` by [Interop/Terminal/TerminalBridge.cs](Interop/Terminal/TerminalBridge.cs). xterm.js bundle lives under `Assets/web/`.
- **Threading**: UI thread is STA. Use `Task.Run` for SSH/SFTP I/O, marshal back via `DispatcherQueue.TryEnqueue`.

## Packaging

- Unpackaged (`WindowsPackageType=None`). Do not switch to MSIX without auditing the ActiveX host path — packaged identity changes ActiveX behavior and may require `runFullTrust`.
- x64 and arm64 only. No x86.

## What this scaffold does NOT do yet

- SSH protocol surface (`SshSessionService` throws `NotImplementedException`).
- RDP host (`RdpHostForm`/`RdpSessionService` throw `NotImplementedException`).
- SFTP browser (`SftpService` throws `NotImplementedException`).
- Connection editor UI (`ConnectionEditorPage` is a placeholder).
- Real connection tree (the tree binds to an empty SQLite DB on first run).
- Installer (`scripts/Build-Installer.ps1` is a `-DryRun`-only scaffold).
- xterm.js bundle (`Assets/web/terminal.html` is a placeholder; drop the JS in during the SSH feature PR).

Each item above is a follow-up feature PR.
