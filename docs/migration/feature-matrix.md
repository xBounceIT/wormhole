# Phase 0 — Shipped feature matrix

Baseline commit: `fc0337e0e8b4d6178ddf6c6838b1c45a8aecf60f` (app **0.9.0**).  
Columns: **Area | Feature | Entry points (files) | Parity notes | WinUI | Rust | Risk**.  
Risk = migration difficulty / behavioral-parity hazard for Rust/GPUI (**Low / Med / High**).  
Only **shipped** behavior (README “What works today” + code); Planned items omitted.

### Status legend

| Value | Meaning |
|---|---|
| **Production** | Shipping WinUI 3 / .NET app (only column allowed to claim this) |
| **Lab** | Parallel Rust library/lab with tests; not product UI / not cutover |
| **Spike** | Exploratory or partial (stubs, feature gates, no live engine/UI wiring) |
| **Pending** | No meaningful Rust landing yet |

**Rule:** Rust stays **Lab / Spike / Pending** until Phase 7 cutover. Never mark Rust as Production here. WinUI remains the production app; the `rust/` workspace is parallel only — see [README.md](README.md).

---

## Connection tree & inheritance

| Area | Feature | Entry points (files) | Parity notes | WinUI | Rust | Risk |
|---|---|---|---|---|---|---|
| Tree | Folder/connection tree with sort order, expand/collapse | `ViewModels/ConnectionTreeViewModel.cs`, `Views/Controls/ConnectionTreeView.xaml(.cs)`, `Data/Repositories/ConnectionRepository.cs`, `Models/ConnectionNode.cs`, `Models/NodeKind.cs` | SQLite `Nodes` table; parent FK + cascade; `SortOrder` / parent index migrations | Production | Lab — domain nodes + storage repo + tree VM ([02-domain.md](02-domain.md), [03-storage.md](03-storage.md), [17-tree-settings-vm.md](17-tree-settings-vm.md)); no GPUI tree chrome cutover | Med |
| Tree | Debounced search (capped matches) | `ConnectionTreeViewModel.cs` (`MaxDisplayedSearchMatches=500`, 120ms debounce) | Search disables drag-reorder; expansion overrides while filtering | Production | Lab — tree VM search helpers ([17-tree-settings-vm.md](17-tree-settings-vm.md)); UI wiring Pending | Med |
| Tree | Drag-reorder / reparent | `ConnectionTreeViewModel.cs`, `ConnectionTreeView.xaml.cs` | Rejects invalid selections (ancestor+descendant, search mode) | Production | Lab — tree reparent/drag validation glue + Fake/`reparent_connection` apply ([17-tree-settings-vm.md](17-tree-settings-vm.md)); GPUI drag UX Pending | Med |
| Tree | Connect / edit / duplicate / delete / new folder / new connection | `ConnectionTreeViewModel.cs`, `Services/DialogService.cs`, `Views/Dialogs/NewConnectionDialog.xaml(.cs)`, `Views/Dialogs/FolderEditorDialog.xaml(.cs)` | Real editor is dialog, not legacy `Views/Pages/ConnectionEditorPage.xaml` | Production | Lab — connection-editor + folder CRUD helpers (`create_folder` / `rename_folder` / `delete_folder`) ([20-connection-editor.md](20-connection-editor.md), [03-storage.md](03-storage.md)); dialogs/GPUI Pending | Med |
| Inheritance | Folder-level inheritance of protocol settings, credentials, RDP knobs, serial, tunnel tri-state | `Data/InheritanceResolver.cs`, `Services/ConnectionProfileResolver.cs`, `Models/ConnectionProfile.cs` | **Load-bearing domain concept** (mRemoteNG parity). Cycle detection; cross-protocol port discard; credential identity boundaries; `TunnelEnabled` null/false/true; inline password leaf-only | Production | Lab — `wormhole-domain::InheritanceResolver` ([02-domain.md](02-domain.md)) | **High** |
| Inheritance | Credential binding modes (inherit / none / saved) | `Models/CredentialBindingMode.cs`, `Services/ConnectionCredentialBindingService.cs`, migration `0012_credential_inheritance.sql` | Legacy null+CredentialId shapes still interpreted | Production | Lab — enum + resolver parity in `wormhole-domain` ([02-domain.md](02-domain.md)); binding service UI Pending | High |
| Inheritance | Live refresh when node rows change | `Services/ConnectionNodeChangeNotifier.cs`, tree + session VMs | Open tabs can refresh resolved profiles carefully (SSH fingerprint preservation) | Production | Spike — `wormhole-domain` Fake pub/sub (`ConnectionNodeChangeEvent` metadata-only create/update/delete/reparent; no secrets) ([02-domain.md](02-domain.md), [adversarial-ledger-node-change-notifier.md](adversarial-ledger-node-change-notifier.md)); tree/session GPUI subscribers Pending | Med |

---

## Credentials & secrets

| Area | Feature | Entry points (files) | Parity notes | WinUI | Rust | Risk |
|---|---|---|---|---|---|---|
| Creds UI | Credentials page CRUD | `ViewModels/CredentialsViewModel.cs`, `Views/Pages/CredentialsPage.xaml(.cs)`, `Views/Dialogs/CredentialDialog.xaml(.cs)`, `Data/Repositories/CredentialRepository.cs`, `Models/CredentialProfile.cs` | Metadata in SQLite; secrets elsewhere | Production | Pending — secrets APIs Lab; credentials page UI not landed | Med |
| Creds | Password store (Windows Credential Manager) | `Services/CredentialService.cs` (`Wormhole:<guid>`) | 2560-byte CredMgr limit; LocalMachine persistence | Production | Lab — `wormhole-secrets-win` CredMgr + size guard ([04-secrets.md](04-secrets.md)) | **High** |
| Creds | SSH private keys (DPAPI files) | `CredentialService.cs` → `%LOCALAPPDATA%\Wormhole\keys\<id>.dpapi` | Keys too large for CredMgr | Production | Lab — DPAPI key files ([04-secrets.md](04-secrets.md)) | High |
| Creds | Inline per-connection password (SSH/RDP) | `ConnectionNode.UseInlinePassword`, CredMgr keyed by **node Id**, `ConnectionEditorViewModel`, `NewConnectionDialog` | Not inherited; mutually exclusive with saved credential | Production | Lab — CredMgr keying + editor state + `save_validated_editor` ([04-secrets.md](04-secrets.md), [20-connection-editor.md](20-connection-editor.md), [03-storage.md](03-storage.md)) | High |
| Creds | Connect-time / transient passwords | `Services/ITransientSessionCredentialStore.cs`, Quick Connect + session prompts | Ephemeral; never SQLite | Production | Lab — `wormhole-secrets-win::transient_session` (`Memory`/`Fake`; never SQLite/CredMgr/DPAPI) ([04-secrets.md](04-secrets.md)); QC state ([21-quick-connect.md](21-quick-connect.md)); shell/session DI wiring Pending | Med |
| Creds | Password resolution (local vs Bitwarden) | `Services/CredentialPasswordResolver.cs`, `Services/Ssh/SshCredentialResolver.cs` | Bitwarden resolves live via `bw`; unlock prompt when locked | Production | Spike — `StubBitwardenSession` / Fake; `bw` spawn not wired ([04-secrets.md](04-secrets.md)) | High |
| Creds | Credential picker search | `ViewModels/CredentialPickerSearch.cs` | Shared by editor / session prompts | Production | Lab — `wormhole-ui::credential_picker` Fake list + name/username(/domain) filter ([20-connection-editor.md](20-connection-editor.md), [adversarial-ledger-credential-picker.md](adversarial-ledger-credential-picker.md)); SQLite catalog / GPUI Pending | Low |
| App lock | App authentication (Disabled / PIN / Password / Windows Hello + fallback) | `Services/Security/*`, `Models/AppAuthenticationMode.cs`, Settings Security tab | Verifier in `app-auth.dpapi` via `DpapiAppAuthenticationDataProtector` (entropy `Wormhole.AppAuthentication.v1`); Hello disabled in remote sessions (`RemoteDesktopSessionDetector` + `SM_REMOTESESSION`); idle lock | Production | Spike — app-auth DPAPI + PIN/password `AppAuthenticationService` (Fake protector; fail-closed verify) + Hello `AvailabilityProbe` / `HelloPrompt` stubs; unlock UI glue (`wormhole-app::hello_unlock` Fake Success/Cancel/Unavailable); WinRT consent not wired ([04-secrets.md](04-secrets.md), [15-cutover.md](15-cutover.md)) | High |
| Logging | Secret redaction expectation | Serilog setup in `App.xaml.cs`; comments across auth paths | Never log passwords / tokens / keys | Production | Lab — `wormhole-app` tracing redaction ([13-update-logging.md](13-update-logging.md)) | Med |

---

## SSH

| Area | Feature | Entry points (files) | Parity notes | WinUI | Rust | Risk |
|---|---|---|---|---|---|---|
| SSH | Session lifecycle / reconnect / credential prompt | `ViewModels/Sessions/SshSessionViewModel.cs`, `Services/SshSessionService.cs`, `Services/Ssh/SshSession.cs` | SSH.NET; STA UI + `Task.Run` I/O | Production | Spike — russh client + session orch password path ([06-ssh-spike.md](06-ssh-spike.md), [16-session-orchestrator.md](16-session-orchestrator.md)); reconnect/backoff **policy** stub (`wormhole_ssh::reconnect` / Fake schedule); UI reconnect loop Pending | High |
| SSH | xterm.js terminal in WebView2 | `Views/Sessions/SshTerminalView.xaml(.cs)`, `Interop/Terminal/TerminalBridge.cs`, `TerminalOutputPump.cs`, `TerminalInputWriter.cs`, `TerminalReplayBuffer.cs`, `Assets/web/` | Shared WebView2 env under `webview2\`; exact-replay on tab switch; process-exit recovery / rebind | Production | Lab — wire protocol + gate 5 / clipboard ([14-terminal-bridge.md](14-terminal-bridge.md), [01-surface-lab.md](01-surface-lab.md)); product tab host Pending | **High** |
| SSH | Auth: password, private key, keyboard-interactive paths | `Services/Ssh/SshAuthMethodsBuilder.cs`, `SshNetPrivateKeyInspector.cs` | Key files from DPAPI store | Production | Spike — password/key via `client` feature; agent + kbi wire auth `AuthNotImplemented`; KBI multi-prompt Fake channel always on ([06-ssh-spike.md](06-ssh-spike.md)) | High |
| SSH | Host key pin / mismatch prompt | `Services/Ssh/SshHostKeyValidator.cs`, `SshHostKeyMismatchException.cs`, profile `SshKnownHostFingerprint` | Persisted on accept for saved nodes; **not** for ephemeral Quick Connect | Production | Lab — `KnownHostsStore` + `verify_host_key_on_connect` (Accept/Reject/Prompt) + `resolve_host_key_prompted` / `FakeKnownHosts` ([06-ssh-spike.md](06-ssh-spike.md)); GPUI/WinUI dialog Pending | Med |
| SSH | Auto-sudo after connect | `Services/Ssh/SshAutoSudoDriver.cs`, migration `0008_ssh_auto_sudo.sql` | Uses captured password | Production | Lab — detector + `AutoSudoSessionGlue` / `FakeTerminalSession` stub; live shell Pending ([06-ssh-spike.md](06-ssh-spike.md)) | Med |
| SSH | SOCKS5 via tunnel | `SshSessionViewModel` + `Services/Tunneling/Socks5Client.cs` | When `TunnelEnabled` after inheritance + route prompt | Production | Lab — `select_ssh_connect_target` / FakeTunnelSocks route glue (Serial never; fail-closed missing SOCKS); dial CONNECT still stub ([06-ssh-spike.md](06-ssh-spike.md), [07-tunnels-mcp.md](07-tunnels-mcp.md), [adversarial-ledger-ssh-socks-route.md](adversarial-ledger-ssh-socks-route.md)) | High |
| SSH | Font / size / auto-copy selection | `Models/AppSettings.cs`, Settings General, terminal bridge | Cascadia Mono default | Production | Lab — settings VM fields + terminal apply glue (`settings_apply` / Fake; empty/whitespace font incl. NBSP / non-positive size fail-closed; auto-copy skips empty+oversize) ([17-tree-settings-vm.md](17-tree-settings-vm.md), [14-terminal-bridge.md](14-terminal-bridge.md)); live xterm options Pending | Low |
| SSH | MCP registration of live sessions | `Services/Mcp/McpSessionRegistry.cs` | Only already-open SSH tabs | Production | Lab — `FakeMcpSessionRegistry` register/unregister Connected ids ([07-tunnels-mcp.md](07-tunnels-mcp.md)); HTTP tool dispatch / live tab scan Pending | Med |

---

## SFTP (file transfer — not a session protocol)

| Area | Feature | Entry points (files) | Parity notes | WinUI | Rust | Risk |
|---|---|---|---|---|---|---|
| SFTP | Dual-pane file transfer dialog from connected SSH tab | `Views/Dialogs/FileTransferDialog.xaml(.cs)`, `ViewModels/Sessions/Transfer/*`, `Services/FileTransferDialogService.cs`, `Services/SftpService.cs`, `Services/Ssh/SftpSession.cs`, `Services/Sftp/FileTransferOrchestrator.cs` | `ProtocolType` has **no** SFTP (value 2 retired — migration `0009`); transfer only from SSH | Production | Lab — dialog glue (`ConnectedSshContext` → SOCKS + cancel queue); dual-pane UI Pending ([11-sftp.md](11-sftp.md)) | High |
| SFTP | Background pre-warm of SFTP client | `SshSessionViewModel` (`_prewarmedSftpSession`, `BorrowTunnelForSftp`) | Separate SSH.NET SftpClient; can borrow tunnel lease | Production | Lab — Fake prewarm / borrow glue (`SftpPrewarmGlue` / `BorrowedShellTunnel`); live russh dial Pending ([11-sftp.md](11-sftp.md)) | High |
| SFTP | Upload/download/queue, conflict overlay, local quick paths, drag targets | `FileTransferOrchestrator.cs`, `TransferDropTarget.cs`, `LocalQuickPaths.cs`, `Views/Controls/FilePaneControl.xaml(.cs)`, `TransferQueueStrip.xaml(.cs)` | Local pane can shell-open paths via `Process.Start` | Production | Lab — serialized queue / single-flight cancel + progress callback glue ([11-sftp.md](11-sftp.md)); overlays/drag / strip binding Pending | Med |
| SFTP | SOCKS5 through same tunnel as SSH | `SftpService` / session tunnel borrow | Must not tear down shared tunnel early | Production | Spike — SOCKS target selection stub; live `russh-sftp` deferred ([11-sftp.md](11-sftp.md)) | High |
| UI | Legacy SFTP browser page exists | `Views/Pages/SftpBrowserPage.xaml(.cs)` | Prefer dialog path as primary shipped UX | Production | Pending (intentionally deprioritized) | Low |

---

## Serial

| Area | Feature | Entry points (files) | Parity notes | WinUI | Rust | Risk |
|---|---|---|---|---|---|---|
| Serial | Local COM terminal (`ProtocolType.Serial = 5`) | `Services/SerialSessionService.cs`, `Services/Serial/SerialSession.cs`, `ViewModels/Sessions/SerialSessionViewModel.cs`, migration `0013_serial_protocol.sql`, `Models/SerialSettings.cs` | Host = COM line (`COM1`, `\\.\COM10`, …); `System.IO.Ports` | Production | Lab — `wormhole-serial` session + enumerate + `wormhole-ui::SerialPortPickerState` host glue + orch dispatch ([16-session-orchestrator.md](16-session-orchestrator.md), [20-connection-editor.md](20-connection-editor.md)); GPUI terminal / COM combo Pending | Med |
| Serial | PuTTY-style line settings | baud / data bits / stop bits / parity / flow (None, XON-XOFF, RTS-CTS, DSR-DTR) | Inherited like other node fields; defaults **9600 8N1, flow None** | Production | Lab — domain enums + `serial_settings_from_profile` + `SerialLineCombo` / `wormhole-ui` `serial_presets` editor↔node glue ([02-domain.md](02-domain.md), [20-connection-editor.md](20-connection-editor.md)); GPUI Serial tab Pending | Med |
| Serial | Reuses SSH xterm.js / `TerminalBridge` | `SshTerminalView` + `ITerminalSessionViewModel` | **No** credentials, **no** VPN routing | Production | Lab — shared `wormhole-terminal` traits ([14-terminal-bridge.md](14-terminal-bridge.md)) | Med |

---

## HTTP / HTTPS

| Area | Feature | Entry points (files) | Parity notes | WinUI | Rust | Risk |
|---|---|---|---|---|---|---|
| Web | Embedded WebView2 browser tabs (`Http=3`, `Https=4`) | `ViewModels/Sessions/HttpSessionViewModel.cs`, `Views/Sessions/WebBrowserView.xaml(.cs)` | Address = `host[:port]`; no path column; no Wormhole credentials | Production | Spike — `HttpConnectionTarget` + orch + Fake nav-result→status glue; WebView2 host in `wormhole-surface-win` lab ([10-http.md](10-http.md), [16-session-orchestrator.md](16-session-orchestrator.md)) | High |
| Web | Ignore certificate errors (HTTPS) | `HttpIgnoreCertErrors`, migration `0011_http_ignore_cert_errors.sql`, `ServerCertificateErrorDetected=AlwaysAllow` | Needed for appliances; also for loopback-forwarder HTTPS; leaf-only (not folder-inherited) | Production | Lab — `HttpCertPolicy` + leaf→AlwaysAllow **mapping** glue (COM subscribe not in lab create) ([10-http.md](10-http.md)) | Med |
| Web | Tunnel hybrid routing | SOCKS5 `--proxy-server=` when available; else `BindLocalForwarderAsync` | SOCKS preserves real hostname/SNI; loopback needs ignore-cert | Production | Lab — `select_http_tunnel_route` ([10-http.md](10-http.md)) | **High** |
| Web | Isolated / shared WebView2 profiles; startup wipe of non-extension web root | `Helpers/AppPaths.cs`, `App.xaml.cs` (`ClearWebBrowserUserData`), `Helpers/WebViewBrowserArguments.cs` | Argument-fingerprinted folders avoid `ERROR_INVALID_STATE` | Production | Spike — `profile_wipe` Fake glue (keyed fingerprint / shared vs isolated / wipe leaves Bitwarden) ([10-http.md](10-http.md)); live disk wipe / WebView2 env create Pending | High |
| Web | New-window handling / Bitwarden popups | `Helpers/WebViewNewWindowNavigation.cs`, `WebBrowserView.xaml.cs`, `Services/BitwardenBrowser/*` | No unmanaged popups; extension popups hosted in-app | Production | Pending | High |

---

## VNC

| Area | Feature | Entry points (files) | Parity notes | WinUI | Rust | Risk |
|---|---|---|---|---|---|---|
| VNC | Embedded client (`ProtocolType.Vnc = 6`) | `Services/VncSessionService.cs`, `ViewModels/Sessions/VncSessionViewModel.cs`, `Views/Sessions/VncView.xaml(.cs)` | `Community.MarcusW.VncClient` | Production | Spike — protocol/auth types + connect target; live TCP deferred even with `engine` ([09-vnc.md](09-vnc.md)); session orch fails closed | High |
| VNC | Auth: none + classic VNC password only | `PasswordProviderAuthenticationHandler` in `VncSessionService` | Username/domain hidden/optional in UI; no advanced auth | Production | Lab — `auth_glue` (`select_vnc_auth` / `provide_vnc_auth_input` / `FakeVncPasswordProvider`; username/domain ignored; empty/`AuthCancelled` fail-closed; Debug redacts) ([09-vnc.md](09-vnc.md), [adversarial-ledger-vnc-password-auth.md](adversarial-ledger-vnc-password-auth.md)) | Med |
| VNC | Tunnel via local TCP forwarder | `BindLocalForwarderAsync` (same as RDP data path) | No RDP-specific gateway/cert rejects | Production | Lab — `select_vnc_connect_target` + tunnels forwarder ([09-vnc.md](09-vnc.md), [07-tunnels-mcp.md](07-tunnels-mcp.md)) | High |
| VNC | Input / framebuffer rendering | `VncView.xaml.cs` | WinUI render target + pointer/keyboard mapping | Production | Lab — `RawPixelBuffer` + `InputEventQueue` + `session_glue` (`FakeFramebufferDirtyNotify`; fail-closed when not Connected; apply errors skip dirty notify) + `clipboard_glue` (ClientCutText → Fake send / ServerCutText → local buffer; 1 MiB soft cap; empty fail-closed; Debug lengths only); orch still `UnsupportedProtocol`; GPUI surface Pending ([09-vnc.md](09-vnc.md)) | High |

---

## RDP

| Area | Feature | Entry points (files) | Parity notes | WinUI | Rust | Risk |
|---|---|---|---|---|---|---|
| RDP | Embedded ActiveX (`MsRdpClient*NotSafeForScripting`) | `Interop/Rdp/AxMsRdpClient9.cs`, `MsTscAxEventsSink.cs`, `RdpHostForm.cs`, `Services/RdpSessionService.cs`, `ViewModels/Sessions/RdpSessionViewModel.cs` | Prefers Client11→10→9 CLSID via registry probe; dynamic `GetOcx()`; events via `IConnectionPointContainer` | Production | Spike — `wormhole-surface-win` feature `rdp` OLE/CredSSP configure ([05-rdp-spike.md](05-rdp-spike.md)); session orch typed stub fails closed ([16-session-orchestrator.md](16-session-orchestrator.md)) | **High** |
| RDP | Owned top-level overlay (not SetParent child) | `Views/Sessions/RdpSurfaceHost.xaml(.cs)`, `Helpers/RdpOverlayCoordinator.cs`, `Helpers/Win32Interop.cs` | WinUI airspace: overlay owned via `GWLP_HWNDPARENT`, positioned with `MoveWindow`/`SetWindowPos` each layout tick; subclass owner for drag sync; hide during ContentDialogs | Production | Spike — owned-overlay broker path ([05-rdp-spike.md](05-rdp-spike.md), [native-surface-broker.md](native-surface-broker.md)) | **High** |
| RDP | Full RDP property surface (display, redirects, gateway, NLA/CredSSP, performance flags, dynamic resolution) | `RdpHostForm.cs`, `ConnectionNode` / `ConnectionProfile` RDP fields, migrations `0003_rdp_extras` … `0007_rdp_server_auth_warn_mapping` | Many optional IDispatch properties TrySet | Production | Spike — CredSSP / gateway / strict-auth / resolution + **display/redirect Fake glue** ([05-rdp-spike.md](05-rdp-spike.md)); audio/perf/live OCX apply Pending | High |
| RDP | External `mstsc.exe` fallback | `RdpSessionViewModel` (`Process.Start("mstsc.exe")`), `Helpers/AzureAdCredentialDetector.cs`, migrations `0004`–`0006` | AAD/WAM; crash-sentinel auto-flag (`Services/Rdp/RdpCrashSentinelService.cs`, `App.xaml.cs`) | Production | Pending | High |
| RDP | Tunnel: `BindLocalForwarderAsync` → connect OCX to `127.0.0.1:local` | `RdpSessionViewModel.PrepareConnectProfileAsync`, `Services/Tunneling/LocalTcpForwarder.cs` | **Rejected** combos with tunnel: external mstsc, RD Gateway, strict server auth | Production | Lab — `LocalForwarder` + tunnel policy helpers ([07-tunnels-mcp.md](07-tunnels-mcp.md), [05-rdp-spike.md](05-rdp-spike.md)) | **High** |
| RDP | Drive list / desktop size helpers | `Helpers/RdpDriveList.cs`, `RdpDesktopSizeResolver.cs`, `RdpScreenSizes.cs` | Win32 / display enumeration | Production | Lab — `RdpScreenSizes` in domain; connect-time resolve + drive parse in display/redirect Fake glue ([05-rdp-spike.md](05-rdp-spike.md)); live DriveCollection enum Pending | Med |
| RDP | STA requirement | WinForms `RdpHostForm` on UI/STA | Non-negotiable for OCX | Production | Spike — documented in RDP spike; host still lab-only ([05-rdp-spike.md](05-rdp-spike.md)) | High |

---

## Tunnels / VPN providers

| Area | Feature | Entry points (files) | Parity notes | WinUI | Rust | Risk |
|---|---|---|---|---|---|---|
| Tunnels UI | Tunnel configs page + editor + test dialog | `ViewModels/TunnelConfigsViewModel.cs`, `TunnelPickerViewModel.cs`, `TunnelTestDialogViewModel.cs`, `Views/Pages/TunnelConfigsPage.xaml`, `Views/Dialogs/TunnelDialog.xaml`, `TunnelTestDialog.xaml` | Metadata SQLite (`TunnelConfig`); secret DPAPI file | Production | Pending — DPAPI tunnel secrets Lab ([04-secrets.md](04-secrets.md)); page UI not landed | High |
| Core | Ref-counted shared leases, coalesce establish, invalidate on `UpdatedAt` / Failed/Closed | `Services/Tunneling/TunnelManager.cs`, `BorrowedTunnelInstance.cs`, `SocksTunnelInstance.cs`, `ITunnelInstance.cs` | One OTP prompt for concurrent tabs | Production | Lab — `wormhole-tunnels::TunnelManager` ([07-tunnels-mcp.md](07-tunnels-mcp.md)) | **High** |
| Core | Route prompt (tunnel vs direct) | `TunnelRoutePrompter.cs`, setting `PromptBeforeTunnelConnect` | On by default | Production | Pending | Med |
| Core | OTP / TLS trust prompts | `DialogOtpPromptService.cs`, `DialogTlsTrustPromptService.cs` | Shared across providers | Production | Spike — `OtpPrompt` Memory/Fake/Channel + UI glue `OtpPromptChannel`/`FakeOtpPromptUi` (no GPUI dialog; [adversarial-ledger-otp-ui.md](adversarial-ledger-otp-ui.md)); TLS trust UI Pending ([07-tunnels-mcp.md](07-tunnels-mcp.md)) | Med |
| Core | Physical path / split-routing heuristics | `WindowsPhysicalNetworkPathService.cs` | Win32 `dnsapi` / `iphlpapi` P/Invokes | Production | Pending | High |
| WireGuard | Userspace sidecar | `Services/Tunneling/WireGuard/*`, `tools/wormhole-wgproxy`, `wormhole-wgproxy.exe` | SOCKS5 READY protocol | Production | Lab — sidecar spawn via `SidecarProcess` ([07-tunnels-mcp.md](07-tunnels-mcp.md)); product UX Pending | High |
| OpenVPN | Shared sidecar | `Services/Tunneling/OpenVpn/*`, `tools/wormhole-ovpnproxy`, `wormhole-ovpnproxy.exe` | Release requires real OpenVPN3 PE | Production | Lab — shared ovpn sidecar path + auth_glue ([07-tunnels-mcp.md](07-tunnels-mcp.md)) | High |
| Fortinet | Username/password + TOTP; SAML embedded WebView2 or external browser (loopback callback default **8020**) | `Services/Tunneling/Fortinet/*`, `wormhole-fortiproxy.exe` | Ephemeral `auth_id` / `SVPNCOOKIE` via stdin only; realm incompatible with external SSO; pin rejects embedded SSO | Production | Spike — sidecar spawn + `SamlAuthFlow` + `ChannelSamlAuthCallback` / UI glue `SamlPromptChannel`/`FakeSamlPromptUi` (no full WebView2/OS-browser UI; [adversarial-ledger-fortinet-saml-ui.md](adversarial-ledger-fortinet-saml-ui.md)) ([07-tunnels-mcp.md](07-tunnels-mcp.md)) | **High** |
| WatchGuard | Portal + OpenVPN data plane; profile DPAPI cache; SAML dialog | `Services/Tunneling/Watchguard/*` | OTP reuse / cache carefully ordered | Production | Spike — Firebox auth stub; not wired into establish ([07-tunnels-mcp.md](07-tunnels-mcp.md)) | High |
| Stormshield | Portal config download + OpenVPN; DPAPI cache; OTP reuse guard | `Services/Tunneling/Stormshield/*` | Single-use OTP must hit data plane, not HTTPS step on reconnect | Production | Spike — SNS auth stub + establish-path glue (`establish_stormshield` / `_sns`; portal/cache/SSO pending) ([07-tunnels-mcp.md](07-tunnels-mcp.md)) | High |
| Azure VPN | Entra ID OAuth (WebView2) + refresh-token DPAPI cache; OpenVPN with user `AzureAD` | `Services/Tunneling/AzureVpn/*` | Interactive popup; silent refresh | Production | Spike — `EntraTokenProvider` stub; interactive WebView2 popup not wired ([07-tunnels-mcp.md](07-tunnels-mcp.md)) | **High** |
| Cisco Secure Client | Aggregate-auth + CSTP via Go sidecar (not local Cisco UI) | `Services/Tunneling/CiscoSecureClient/*`, `tools/wormhole-ciscoproxy` | v1: user/pass + optional group + TOTP/secondary; **no** SAML/cert/CSD | Production | Spike — aggregate-auth typing stub; no STF/CSTP ([07-tunnels-mcp.md](07-tunnels-mcp.md)) | High |
| Routing matrix | SSH/SFTP → SOCKS5; RDP/VNC → local forwarder; HTTP → SOCKS proxy args else forwarder; Serial → never | Documented in README / `AGENTS.md` | Parity table for golden tests | Production | Lab — hooks in tunnels/http/ssh/sftp/session orch ([07-tunnels-mcp.md](07-tunnels-mcp.md), [16-session-orchestrator.md](16-session-orchestrator.md)); end-to-end product Pending | **High** |

---

## Bitwarden

| Area | Feature | Entry points (files) | Parity notes | WinUI | Rust | Risk |
|---|---|---|---|---|---|---|
| Vault | Optional CLI vault (`bw`) for credential passwords | `Services/Bitwarden/*`, Settings Extensions, migrations `0014`/`0015` | Session key **memory-only**; SQLite stores item refs + display cache only | Production | Spike — memory-only session stub; CLI spawn not wired ([04-secrets.md](04-secrets.md)) | High |
| Vault | Install/update CLI; login/unlock/sync | `BitwardenCliInstaller.cs`, `BitwardenCliVaultClient.cs`, `BitwardenCredentialSyncService.cs` | Official GitHub releases + pinned hashes in settings | Production | Pending | Med |
| Vault | Virtual read-only credentials in UI/pickers | `BitwardenCredentialCatalogService.cs`, `BitwardenVirtualCredentialIds.cs` | Resolve password at connect | Production | Pending | High |
| Browser | Official extension in HTTPS WebView2 profiles | `Services/BitwardenBrowser/*`, `WebBrowserView.xaml.cs` | Persistent profiles; shared storage DPAPI file; never wipe cookies/IDB; flush on shutdown/update | Production | Spike — profile folder/arg helpers in `wormhole-http` ([10-http.md](10-http.md)); extension host Pending | **High** |
| Browser | Manual ZIP/folder install stays pinned | Settings + installer services | Offline/enterprise | Production | Pending | Med |
| Onboarding | Notice versioning | `BitwardenOnboardingNoticeService.cs`, settings schema | Soft UX only | Production | Pending | Low |

---

## MCP (AI agent control)

| Area | Feature | Entry points (files) | Parity notes | WinUI | Rust | Risk |
|---|---|---|---|---|---|---|
| MCP | Opt-in loopback Streamable HTTP MCP server | `Services/Mcp/McpServerHost.cs`, `McpSshTools.cs`, `McpSessionRegistry.cs`, Settings (MCP section), `ModelContextProtocol.AspNetCore` | Default `http://127.0.0.1:8765`; off by default | Production | Lab — `wormhole-mcp` `rmcp` Streamable HTTP + loopback bind ([07-tunnels-mcp.md](07-tunnels-mcp.md)); Settings toggle Pending | High |
| MCP | Bearer token in CredMgr (fixed guid) | `McpServerHost.TokenCredentialId` | Reveal/copy/regenerate in Settings; client config JSON helpers | Production | Lab — CredMgr/`MemoryTokenStore` + generate/authorize helpers ([07-tunnels-mcp.md](07-tunnels-mcp.md)) | High |
| MCP | Tools: `list_sessions`, `run_command`, `send_text`, `read_terminal` | `McpSshTools.cs` + SSH `ShellCommandRunner` | First action per session requires UI approval; **no** open-connection / read-creds tools | Production | Lab — tool defs + `SessionApprovalGate` + `FakeMcpSessionRegistry` ([07-tunnels-mcp.md](07-tunnels-mcp.md)); live SSH runner / HTTP dispatch wiring Pending | High |
| MCP | Clean shutdown vs WebView2 flush | `MainWindow.xaml.cs` | Ordering matters on exit | Production | Pending | Med |

---

## Import / backup / update

| Area | Feature | Entry points (files) | Parity notes | WinUI | Rust | Risk |
|---|---|---|---|---|---|---|
| Import | mRemoteNG `confCons.xml` (SSH/RDP/VNC only) | `Services/MRemoteNg/*`, `ViewModels/MRemoteNgImportDialogViewModel.cs`, `Views/Dialogs/MRemoteNgImportDialog.xaml` | AES-GCM **16-byte nonce** via BouncyCastle (not `AesGcm`); passwords → CredMgr on commit; HTTP/HTTPS/Serial soft-skipped | Production | Spike — XML parse/plan + decrypt + apply stub + soft-skip `ImportSkipReport` (HTTP/HTTPS/Serial labeled samples; no separate per-protocol tallies); CredMgr/GPUI Pending ([12-import.md](12-import.md), [adversarial-ledger-import-skip-report.md](adversarial-ledger-import-skip-report.md)) | High |
| Backup | Export/import nodes, credentials, tunnels, Bitwarden **refs/cache**, passwords, keys, tunnel payloads | `Services/Backup/BackupService.cs`, `Models/Backup/BackupDocument.cs`, backup dialogs | Optional password → PBKDF2 (600k) + AES-GCM; caps file size / iterations; **excludes** Bitwarden passwords, WebView2 profiles, extension packages | Production | Spike — backup envelope inspect helpers ([12-import.md](12-import.md)); full round-trip Pending | High |
| Update | GitHub release check / download / launch installer / changelog WebView | `Services/UpdateService.cs`, `ViewModels/UpdateViewModel.cs`, `Views/Controls/UpdateChangelogView.xaml(.cs)`, Settings Updates | Auto-check setting; skip version; prepare-for-install flushes Bitwarden WebViews | Production | Spike — Fake/NetworkStub checker + `check_now` notify glue (Available/None/Error); no live HTTP / installer UX ([13-update-logging.md](13-update-logging.md)) | Med |

---

## Settings & shell UI

| Area | Feature | Entry points (files) | Parity notes | WinUI | Rust | Risk |
|---|---|---|---|---|---|---|
| Settings | General: theme, confirm close, auto-copy, tunnel prompt, SSH font | `Views/Pages/SettingsPage.xaml`, `ViewModels/SettingsViewModel.cs`, `Services/AppSettingsService.cs` | `settings.json` schema v8 | Production | Lab — settings VM + `SettingsStore` ([17-tree-settings-vm.md](17-tree-settings-vm.md), [03-storage.md](03-storage.md)); GPUI page Pending | Med |
| Settings | Security: app lock / Hello / idle | (above) + `Services/Security/*` | | Production | Spike — secrets stubs + PIN/password verifier ([04-secrets.md](04-secrets.md)); Settings Security UI Pending | High |
| Settings | Extensions: Bitwarden vault + browser | (above) | | Production | Pending | High |
| Settings | Updates + MCP | (above) | | Production | Spike — update/MCP libraries Lab/Spike; Settings sections Pending | Med |
| Shell | Navigation: Sessions / Credentials / Tunnels / Settings | `MainWindow.xaml(.cs)`, `Services/NavigationService.cs`, `ViewModels/ShellViewModel.cs` | Custom title bar, Mica, sidebar width | Production | Spike — GPUI shell skeleton (`wormhole-ui` feature `gpui`) ([08-ui.md](08-ui.md)); not a product shell | Med |
| Shell | Tabbed sessions + close confirm | `ShellViewModel.Tabs`, `SessionsPage.xaml(.cs)` | | Production | Lab — session tab bar / tabs state ([17-tree-settings-vm.md](17-tree-settings-vm.md)); confirm UX Pending | Med |
| Shell | Multi-pane splits / drag-drop tiling | `ViewModels/Sessions/Layout/*`, `Views/Sessions/SessionLayoutHost.xaml(.cs)`, `SessionPaneHost`, `PaneSplitter`, `SessionDropOverlay` | Tabs stay in collection; layout is in-memory tiling | Production | Lab — pane layout tree + broker sink ([08-ui.md](08-ui.md), [01-surface-lab.md](01-surface-lab.md)); drag chrome Pending | **High** |
| Shell | Quick Connect (ephemeral full editor) | `ViewModels/QuickConnectViewModel.cs`, `Views/Controls/QuickConnectBar.xaml`, `DialogService.PromptQuickConnectAsync`, `Models/QuickConnectResult.cs` | All session protocols; `IsEphemeral=true`; transient password store | Production | Lab — pure QC state + session-orchestrator connect glue ([21-quick-connect.md](21-quick-connect.md), [16-session-orchestrator.md](16-session-orchestrator.md)); bar/dialog Pending | Med |
| Shell | Connection progress stepper | `Views/Sessions/ConnectionProgressView.xaml`, `ViewModels/Sessions/ConnectionProgress.cs` | Shared UX across protocols | Production | Pending | Low |
| Shell | Content dialog gating / RDP overlay suppress | `Services/ContentDialogGate.cs`, `ContentDialogTracker.cs`, `RdpOverlayCoordinator.cs` | Prevents overlay covering modals | Production | Spike — overlay hide notes in RDP spike; full dialog gate Pending ([05-rdp-spike.md](05-rdp-spike.md)) | High |
| Crash | Crash diagnostics / dumps | `Services/CrashDiagnosticsService.cs`, installer WER keys | | Production | Lab — secrets-free diagnostics report + soak **placeholders** ([19-diagnostics-soak.md](19-diagnostics-soak.md)); WER/dumps Pending | Med |

---

## Persistence / DI / logging (cross-cutting)

| Area | Feature | Entry points (files) | Parity notes | WinUI | Rust | Risk |
|---|---|---|---|---|---|---|
| DB | SQLite + Dapper + migrations | `Data/SqliteConnectionFactory.cs`, `MigrationRunner.cs`, `Data/Migrations/*.sql` | One connection per op; pinned native sqlite fetch | Production | Lab — rusqlite factory + embedded migrations + repos ([03-storage.md](03-storage.md)) | Med |
| DI | Composition root | `App.xaml.cs` | Resolves from `App.Current.Services` | Production | Lab — `wormhole-app` `AppServices` placeholder bag ([07-tunnels-mcp.md](07-tunnels-mcp.md)); not a shipping host | Med |
| Logs | Serilog file sink | `%LOCALAPPDATA%\Wormhole\logs\` | Retention setting | Production | Lab — tracing daily file + redaction ([13-update-logging.md](13-update-logging.md)) | Low |

---

## Risk summary (matrix-level)

Highest migration risk clusters: **InheritanceResolver**, **RDP ActiveX overlay + mstsc/AAD**, **WebView2 surfaces** (terminal + browser + SAML/Entra + Bitwarden), **tunnel lease/routing matrix**, **secrets layout (CredMgr + DPAPI + backup crypto)**, **session split layout**.

### Rust landing snapshot (honest, non-cutover)

| Cluster | Typical Rust status | Primary docs |
|---|---|---|
| Domain / inheritance / storage / settings JSON | Lab | [02-domain.md](02-domain.md), [03-storage.md](03-storage.md) |
| Secrets (CredMgr/DPAPI) + Hello/Bitwarden stubs | Lab / Spike | [04-secrets.md](04-secrets.md) |
| SSH known_hosts / russh client / auto-sudo detector + glue | Lab / Spike | [06-ssh-spike.md](06-ssh-spike.md) |
| Tunnel leases + MCP Streamable HTTP | Lab / Spike | [07-tunnels-mcp.md](07-tunnels-mcp.md) |
| Session orchestrator (Serial/SSH/HTTP; RDP/VNC fail-closed) | Spike / Lab | [16-session-orchestrator.md](16-session-orchestrator.md) |
| Diagnostics report (soak placeholders only) | Lab | [19-diagnostics-soak.md](19-diagnostics-soak.md) |
| RDP OLE overlay / VNC live engine / product GPUI shell | Spike / Pending | [05-rdp-spike.md](05-rdp-spike.md), [09-vnc.md](09-vnc.md), [08-ui.md](08-ui.md), [15-cutover.md](15-cutover.md) |

WinUI **0.9.0** remains Production. No Rust row above implies Phase 7 cutover readiness.
