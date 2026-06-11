<!-- AGENTS.md mirrors this file (this is the canonical copy). When updating one, update both. -->

# Wormhole — Agent guide

Wormhole is a .NET 10 / WinUI 3 Windows desktop app: a tabbed multi-protocol
connection manager (SSH, RDP, SFTP) positioned as a philosophical sequel to
mRemoteNG. This file orients agents touching the codebase.

## Daily workflow

- Build: `dotnet build Wormhole.csproj -c Debug -p:Platform=x64`
- Run tests: `dotnet test Wormhole.Tests/Wormhole.Tests.csproj`
- Run the app: build, then launch the produced `Wormhole.exe` from `bin\x64\Debug\net10.0-windows10.0.19041.0\`.
- Installer: `scripts/Build-Installer.ps1 -Configuration Release -Architecture x64` publishes the app and builds the Inno Setup `.exe` (requires Inno Setup 6). Use `-DryRun` only to inspect paths.
- VPN integration tests (Linux/WSL2 + Docker): `tests/vpn-fixtures/bootstrap.sh` -> `docker compose -f tests/vpn-fixtures/docker-compose.yml up -d` -> `dotnet test Wormhole.Tests.Integration/Wormhole.Tests.Integration.csproj`. See [tests/vpn-fixtures/README.md](tests/vpn-fixtures/README.md). CI runs this on `ubuntu-latest`; locally the tests skip if env vars / sidecar binaries aren't set up.

## Conventions

- Respect WinUI 3 guidelines. Custom title bar, Mica backdrop, per-monitor DPI.
- Never wrap a `ListView`/`GridView` in a `ScrollViewer` — the unbounded measure disables UI virtualization and realizes every item at load (multi-second page hangs). Give the list a bounded height (star-sized grid row or `MaxHeight`) and let its built-in template `ScrollViewer` scroll.
- DI: `Microsoft.Extensions.DependencyInjection` configured in [App.xaml.cs](App.xaml.cs). Resolve from `App.Current.Services`.
- MVVM: `CommunityToolkit.Mvvm` (`ObservableObject`, `[ObservableProperty]`, `[RelayCommand]`). View models live under [ViewModels/](ViewModels).
- Logging: log via `ILogger<T>` from MEL. Serilog is the provider. Logs land in `%LOCALAPPDATA%\Wormhole\logs\`.
- Persistence: SQLite via `Microsoft.Data.Sqlite` + Dapper at `%LOCALAPPDATA%\Wormhole\wormhole.db`. Schema is versioned by `.sql` files in [Data/Migrations/](Data/Migrations) (embedded resources), applied in alphabetical order by [Data/MigrationRunner.cs](Data/MigrationRunner.cs) at startup. Tracking table: `__migration_history`. To add a migration, drop a new `NNNN_description.sql` in that folder. Open connections via `ISqliteConnectionFactory.Open()` — one connection per operation (Microsoft.Data.Sqlite pools).
- Secrets:
  - **Passwords** → Windows Credential Manager via `Meziantou.Framework.Win32.CredentialManager` (key = `Wormhole:<credId>`). 2560-byte limit.
  - **Private keys** → DPAPI-encrypted files under `%LOCALAPPDATA%\Wormhole\keys\` (Credential Manager is too small).
  - **Tunnel payloads** → DPAPI-encrypted files under `%LOCALAPPDATA%\Wormhole\tunnels\`; SQLite stores only the tunnel row metadata.
  - **Never** log credentials. Add a redaction enricher before adding new logging around auth.

## Architecture pillars (the parts to handle with care)

- **Folder-level inheritance** (`Data/InheritanceResolver.cs`) is the load-bearing domain concept. It is the single thing that makes Wormhole feel like mRemoteNG. Always run its tests before touching it.
- **RDP host** must be on STA. The ActiveX `MsRdpClient9NotSafeForScripting` lives in a WinForms `Form` (see [Interop/Rdp/RdpHostForm.cs](Interop/Rdp/RdpHostForm.cs)) reparented into the WinUI 3 main window via Win32 `SetParent`, then positioned by [Views/Sessions/RdpSurfaceHost.xaml.cs](Views/Sessions/RdpSurfaceHost.xaml.cs) on every layout tick. COM interop is hand-rolled in [Interop/Rdp/AxMsRdpClient9.cs](Interop/Rdp/AxMsRdpClient9.cs) and [Interop/Rdp/MsTscAxEventsSink.cs](Interop/Rdp/MsTscAxEventsSink.cs) — no AxImp-generated wrappers; property access is dynamic via `GetOcx()`, events go through `IConnectionPointContainer.Advise` with a managed `IMsTscAxEvents` sink.
- **SSH terminal** is xterm.js inside a `WebView2` bridged to SSH.NET `ShellStream` by [Interop/Terminal/TerminalBridge.cs](Interop/Terminal/TerminalBridge.cs). xterm.js bundle lives under `Assets/web/`.
- **HTTP/HTTPS web browser** (`ProtocolType.Http`/`Https`, enum values 3/4 — 2 is the retired SFTP value, deliberately skipped) renders an appliance/firewall GUI in an embedded `WebView2`. [ViewModels/Sessions/HttpSessionViewModel.cs](ViewModels/Sessions/HttpSessionViewModel.cs) owns the connection lifecycle and computes an `HttpConnectionTarget` (URL + optional SOCKS proxy + cert policy); [Views/Sessions/WebBrowserView.xaml.cs](Views/Sessions/WebBrowserView.xaml.cs) owns the WebView2 (the VM never touches it) and reports navigation results back. No credentials; HTTPS has an "ignore certificate errors" opt-in (`HttpIgnoreCertErrors`, wired through `ServerCertificateErrorDetected = AlwaysAllow`). The address field carries `host[:port]`; there is no path column.
- **Per-connection VPN** is resolved through the same folder-inheritance path as credentials. `TunnelEnabled` is tri-state (`null` = inherit, `false` = override off, `true` = on) and `TunnelConfigId` points at [Models/TunnelConfig.cs](Models/TunnelConfig.cs). [Services/Tunneling/TunnelManager.cs](Services/Tunneling/TunnelManager.cs) loads the row + DPAPI secret and dispatches to the matching provider (WireGuard, OpenVPN, Fortinet, WatchGuard, Stormshield, Azure VPN, Cisco Secure Client). Tunnels are shared per config: `EstablishAsync` returns a ref-counted lease over one live instance per `TunnelConfigId` (concurrent connects coalesce into one establishment — one OTP prompt), and the real tunnel closes when the last session's lease is disposed; dead (`Failed`/`Closed`) or edited configs (`UpdatedAt` bump) get a fresh instance on the next connect. WatchGuard, Stormshield, and Azure VPN all delegate their data plane to the shared OpenVPN sidecar; Azure VPN authenticates with a Microsoft Entra ID access token (interactive WebView2 popup + DPAPI refresh-token cache, see [Services/Tunneling/AzureVpn/](Services/Tunneling/AzureVpn)) sent as the OpenVPN password with username `AzureAD`. Cisco Secure Client (AnyConnect) instead has its own Go sidecar [tools/wormhole-ciscoproxy](tools/wormhole-ciscoproxy) — modeled on the Fortinet one — that speaks the AnyConnect protocol directly (aggregate-auth XML login + STF-framed CSTP tunnel over TLS, gVisor netstack → loopback SOCKS5); it does NOT drive the locally-installed Cisco client. v1 handles username/password + optional group + a TOTP/secondary-password second factor; SAML SSO, client certs, and CSD/HostScan posture are unsupported.
- **VPN runtime routing** applies to SSH terminal sessions and SFTP file-transfer dialogs via the sidecars' loopback SOCKS5 endpoints. RDP — which cannot speak SOCKS5 directly — routes through `ITunnelInstance.BindLocalForwarderAsync`, which binds a 127.0.0.1 listener that bridges to the real target through the tunnel; the entry point is [RdpSessionViewModel.PrepareConnectProfileAsync](ViewModels/Sessions/RdpSessionViewModel.cs). HTTP/HTTPS sessions use a hybrid: when the tunnel exposes `Socks5Endpoint` the WebView2 is created with a `--proxy-server=socks5://…` environment (real hostname preserved → correct SNI/cert/redirects); otherwise they fall back to the same `BindLocalForwarderAsync` loopback bridge as RDP (cert name won't match loopback, so HTTPS over that path needs the ignore-cert opt-in). Three RDP combos are rejected when a tunnel is enabled because the loopback bridge can't safely handle them: external `mstsc.exe` (runs in the host network), RD Gateway (gateway HTTPS would also bypass the forwarder), and strict server authentication (OCX validates the loopback hostname rather than the original server name).
- **Threading**: UI thread is STA. Use `Task.Run` for SSH/SFTP I/O, marshal back via `DispatcherQueue.TryEnqueue`.
- **mRemoteNG import** is implemented in [Services/MRemoteNg/](Services/MRemoteNg) and exposed through the tree context menu. mRemoteNG's AES-GCM shape needs BouncyCastle; do not replace it with `System.Security.Cryptography.AesGcm` without verifying nonce compatibility.

## Packaging

- Unpackaged (`WindowsPackageType=None`). Do not switch to MSIX without auditing the ActiveX host path — packaged identity changes ActiveX behavior and may require `runFullTrust`.
- x64 and arm64 only. No x86.
- MSBuild fetch targets stage xterm.js assets and the VPN sidecars. Missing Go/C++ toolchains warn rather than fail so the app still builds; using a missing tunnel kind surfaces a runtime error.

## Current gaps

- SFTP is not a standalone session protocol — `ProtocolType` is `Ssh`/`Rdp`/`Http`/`Https`. SFTP file transfer is available from connected SSH tabs (see `SftpService` + the File Transfer dialog). Quick Connect and mRemoteNG import remain SSH/RDP-only (no HTTP/HTTPS yet).
- [Views/Pages/ConnectionEditorPage.xaml](Views/Pages/ConnectionEditorPage.xaml) is a legacy placeholder page; the real editor is [Views/Dialogs/NewConnectionDialog.xaml](Views/Dialogs/NewConnectionDialog.xaml).
