# Wormhole — Agent guide

Wormhole is a .NET 10 / WinUI 3 Windows desktop app: a tabbed multi-protocol
connection manager (SSH, RDP, SFTP) positioned as a philosophical sequel to
mRemoteNG. This file orients agents touching the codebase.

## Daily workflow

- Build: `dotnet build Wormhole.csproj -c Debug -p:Platform=x64`
- Run tests: `dotnet test Wormhole.Tests/Wormhole.Tests.csproj`
- Run the app: build, then launch the produced `Wormhole.exe` from `bin\x64\Debug\net10.0-windows10.0.19041.0\`.
- Releases (later): `scripts/Build-Installer.ps1` produces an Inno Setup `.exe`.
- VPN integration tests (Linux/WSL2 + Docker): `tests/vpn-fixtures/bootstrap.sh` → `docker compose -f tests/vpn-fixtures/docker-compose.yml up -d` → `dotnet test Wormhole.Tests.Integration/`. See [tests/vpn-fixtures/README.md](tests/vpn-fixtures/README.md). CI runs this on `ubuntu-latest`; locally the tests skip if env vars / sidecar binaries aren't set up.

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
- **RDP host** must be on STA. The ActiveX `MsRdpClient9NotSafeForScripting` lives in a WinForms `Form` (see [Interop/Rdp/RdpHostForm.cs](Interop/Rdp/RdpHostForm.cs)) reparented into the WinUI 3 main window via Win32 `SetParent`, then positioned by [Views/Sessions/RdpSurfaceHost.xaml.cs](Views/Sessions/RdpSurfaceHost.xaml.cs) on every layout tick. COM interop is hand-rolled in [Interop/Rdp/AxMsRdpClient9.cs](Interop/Rdp/AxMsRdpClient9.cs) and [Interop/Rdp/MsTscAxEventsSink.cs](Interop/Rdp/MsTscAxEventsSink.cs) — no AxImp-generated wrappers; property access is dynamic via `GetOcx()`, events go through `IConnectionPointContainer.Advise` with a managed `IMsTscAxEvents` sink.
- **SSH terminal** is xterm.js inside a `WebView2` bridged to SSH.NET `ShellStream` by [Interop/Terminal/TerminalBridge.cs](Interop/Terminal/TerminalBridge.cs). xterm.js bundle lives under `Assets/web/`.
- **Threading**: UI thread is STA. Use `Task.Run` for SSH/SFTP I/O, marshal back via `DispatcherQueue.TryEnqueue`.

## Packaging

- Unpackaged (`WindowsPackageType=None`). Do not switch to MSIX without auditing the ActiveX host path — packaged identity changes ActiveX behavior and may require `runFullTrust`.
- x64 and arm64 only. No x86.

## What this scaffold does NOT do yet

- SFTP browser (`SftpService` throws `NotImplementedException`).
- Installer (`scripts/Build-Installer.ps1` is a `-DryRun`-only scaffold).

Each item above is a follow-up feature PR.
