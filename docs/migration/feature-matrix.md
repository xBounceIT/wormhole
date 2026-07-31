# Phase 0 Ã¢â‚¬â€ Shipped feature matrix

Baseline commit: `fc0337e0e8b4d6178ddf6c6838b1c45a8aecf60f` (app **0.9.0**).  
Columns: **Area | Feature | Entry points (files) | Parity notes | WinUI | Rust | Risk**.  
Risk = migration difficulty / behavioral-parity hazard for Rust/GPUI (**Low / Med / High**).  
Only **shipped** behavior (README Ã¢â‚¬Å“What works todayÃ¢â‚¬Â + code); Planned items omitted.

### Status legend

| Value | Meaning |
|---|---|
| **Production** | Shipping WinUI 3 / .NET app (only column allowed to claim this) |
| **Lab** | Parallel Rust library/lab with tests; not product UI / not cutover |
| **Spike** | Exploratory or partial (stubs, feature gates, no live engine/UI wiring) |
| **Pending** | No meaningful Rust landing yet |

**Rule:** Rust stays **Lab / Spike / Pending** until Phase 7 cutover. Never mark Rust as Production here. WinUI remains the production app; the `rust/` workspace is parallel only Ã¢â‚¬â€ see [README.md](README.md).

---

## Connection tree & inheritance

| Area | Feature | Entry points (files) | Parity notes | WinUI | Rust | Risk |
|---|---|---|---|---|---|---|
| Tree | Folder/connection tree with sort order, expand/collapse | `ViewModels/ConnectionTreeViewModel.cs`, `Views/Controls/ConnectionTreeView.xaml(.cs)`, `Data/Repositories/ConnectionRepository.cs`, `Models/ConnectionNode.cs`, `Models/NodeKind.cs` | SQLite `Nodes` table; parent FK + cascade; `SortOrder` / parent index migrations | Production | Lab Ã¢â‚¬â€ domain nodes + storage repo + tree VM ([02-domain.md](02-domain.md), [03-storage.md](03-storage.md), [17-tree-settings-vm.md](17-tree-settings-vm.md)); no GPUI tree chrome cutover | Med |
| Tree | Debounced search (capped matches) | `ConnectionTreeViewModel.cs` (`MaxDisplayedSearchMatches=500`, 120ms debounce) | Search disables drag-reorder; expansion overrides while filtering | Production | Lab Ã¢â‚¬â€ tree VM search helpers ([17-tree-settings-vm.md](17-tree-settings-vm.md)); UI wiring Pending | Med |
| Tree | Drag-reorder / reparent | `ConnectionTreeViewModel.cs`, `ConnectionTreeView.xaml.cs` | Rejects invalid selections (ancestor+descendant, search mode) | Production | Lab Ã¢â‚¬â€ tree reparent/drag validation glue + Fake/`reparent_connection` apply ([17-tree-settings-vm.md](17-tree-settings-vm.md)); GPUI drag UX Pending | Med |
| Tree | Connect / edit / duplicate / delete / new folder / new connection | `ConnectionTreeViewModel.cs`, `Services/DialogService.cs`, `Views/Dialogs/NewConnectionDialog.xaml(.cs)`, `Views/Dialogs/FolderEditorDialog.xaml(.cs)` | Real editor is dialog, not legacy `Views/Pages/ConnectionEditorPage.xaml` | Production | Lab Ã¢â‚¬â€ connection-editor + folder CRUD + tree Duplicate glue (`build_duplicate` / `duplicate_connection`; no secret copy) ([20-connection-editor.md](20-connection-editor.md), [17-tree-settings-vm.md](17-tree-settings-vm.md), [03-storage.md](03-storage.md)); dialogs/GPUI Pending | Med |
| Inheritance | Folder-level inheritance of protocol settings, credentials, RDP knobs, serial, tunnel tri-state | `Data/InheritanceResolver.cs`, `Services/ConnectionProfileResolver.cs`, `Models/ConnectionProfile.cs` | **Load-bearing domain concept** (mRemoteNG parity). Cycle detection; cross-protocol port discard; credential identity boundaries; `TunnelEnabled` null/false/true; inline password leaf-only | Production | Lab Ã¢â‚¬â€ `wormhole-domain::InheritanceResolver` ([02-domain.md](02-domain.md)) | **High** |
| Inheritance | Credential binding modes (inherit / none / saved) | `Models/CredentialBindingMode.cs`, `Services/ConnectionCredentialBindingService.cs`, migration `0012_credential_inheritance.sql` | Legacy null+CredentialId shapes still interpreted | Production | Lab Ã¢â‚¬â€ enum + resolver parity in `wormhole-domain` ([02-domain.md](02-domain.md)); binding service UI Pending | High |
| Inheritance | Live refresh when node rows change | `Services/ConnectionNodeChangeNotifier.cs`, tree + session VMs | Open tabs can refresh resolved profiles carefully (SSH fingerprint preservation) | Production | Spike Ã¢â‚¬â€ `wormhole-domain` Fake pub/sub (`ConnectionNodeChangeEvent` metadata-only create/update/delete/reparent; no secrets) ([02-domain.md](02-domain.md), [adversarial-ledger-node-change-notifier.md](adversarial-ledger-node-change-notifier.md)); tree/session GPUI subscribers Pending | Med |

---

## Credentials & secrets

| Area | Feature | Entry points (files) | Parity notes | WinUI | Rust | Risk |
|---|---|---|---|---|---|---|
| Creds UI | Credentials page CRUD | `ViewModels/CredentialsViewModel.cs`, `Views/Pages/CredentialsPage.xaml(.cs)`, `Views/Dialogs/CredentialDialog.xaml(.cs)`, `Data/Repositories/CredentialRepository.cs`, `Models/CredentialProfile.cs` | Metadata in SQLite; secrets elsewhere | Production | Lab — `wormhole-ui::credentials_page_ui` list/search/multi-select + CRUD Fake glue (`CredentialsPageVm` / `FakeCredentialPageStore`; optional `storage` repo + `secrets` catalog/resolver); no GPUI ([20-connection-editor.md](20-connection-editor.md), [adversarial-ledger-credentials-page.md](adversarial-ledger-credentials-page.md)) | Med |
| Creds | Password store (Windows Credential Manager) | `Services/CredentialService.cs` (`Wormhole:<guid>`) | 2560-byte CredMgr limit; LocalMachine persistence | Production | Lab Ã¢â‚¬â€ `wormhole-secrets-win` CredMgr + size guard ([04-secrets.md](04-secrets.md)) | **High** |
| Creds | SSH private keys (DPAPI files) | `CredentialService.cs` Ã¢â€ â€™ `%LOCALAPPDATA%\Wormhole\keys\<id>.dpapi` | Keys too large for CredMgr | Production | Lab Ã¢â‚¬â€ DPAPI key files ([04-secrets.md](04-secrets.md)) | High |
| Creds | Inline per-connection password (SSH/RDP) | `ConnectionNode.UseInlinePassword`, CredMgr keyed by **node Id**, `ConnectionEditorViewModel`, `NewConnectionDialog` | Not inherited; mutually exclusive with saved credential | Production | Lab Ã¢â‚¬â€ CredMgr keying + editor state + `save_validated_editor` ([04-secrets.md](04-secrets.md), [20-connection-editor.md](20-connection-editor.md), [03-storage.md](03-storage.md)) | High |
| Creds | Connect-time / transient passwords | `Services/ITransientSessionCredentialStore.cs`, Quick Connect + session prompts | Ephemeral; never SQLite | Production | Lab Ã¢â‚¬â€ `wormhole-secrets-win::transient_session` (`Memory`/`Fake`; never SQLite/CredMgr/DPAPI) ([04-secrets.md](04-secrets.md)); QC state ([21-quick-connect.md](21-quick-connect.md)); shell/session DI wiring Pending | Med |
| Creds | Password resolution (local vs Bitwarden) | `Services/CredentialPasswordResolver.cs`, `Services/Ssh/SshCredentialResolver.cs` | Bitwarden resolves live via `bw`; unlock prompt when locked | Production | Lab — `CredentialPasswordResolverGlue` / `FakePasswordStore` + `FakeBitwardenVaultPasswords` + session gate; no `bw` spawn ([04-secrets.md](04-secrets.md), [adversarial-ledger-credential-resolve.md](adversarial-ledger-credential-resolve.md)); SSH full resolver + unlock prompt UI Pending | High |
| Creds | Credential picker search | `ViewModels/CredentialPickerSearch.cs` | Shared by editor / session prompts | Production | Lab Ã¢â‚¬â€ `wormhole-ui::credential_picker` Fake list + name/username(/domain) filter ([20-connection-editor.md](20-connection-editor.md), [adversarial-ledger-credential-picker.md](adversarial-ledger-credential-picker.md)); SQLite catalog / GPUI Pending | Low |
| App lock | App authentication (Disabled / PIN / Password / Windows Hello + fallback) | `Services/Security/*`, `Models/AppAuthenticationMode.cs`, Settings Security tab | Verifier in `app-auth.dpapi` via `DpapiAppAuthenticationDataProtector` (entropy `Wormhole.AppAuthentication.v1`); Hello disabled in remote sessions (`RemoteDesktopSessionDetector` + `SM_REMOTESESSION`); idle lock | Production | Spike Ã¢â‚¬â€ app-auth DPAPI + PIN/password `AppAuthenticationService` (Fake protector; fail-closed verify) + Hello stubs + unlock UI glue + idle-lock policy (`AppIdleLockGlue` / `FakeIdleClock`; Disabled/Never; zero/negative fail-closed); WinRT consent / `GetLastInputInfo` not wired ([04-secrets.md](04-secrets.md), [15-cutover.md](15-cutover.md)) | High |
| Logging | Secret redaction expectation | Serilog setup in `App.xaml.cs`; comments across auth paths | Never log passwords / tokens / keys | Production | Lab Ã¢â‚¬â€ `wormhole-app` tracing redaction ([13-update-logging.md](13-update-logging.md)) | Med |

---

## SSH

| Area | Feature | Entry points (files) | Parity notes | WinUI | Rust | Risk |
|---|---|---|---|---|---|---|
| SSH | Session lifecycle / reconnect / credential prompt | `ViewModels/Sessions/SshSessionViewModel.cs`, `Services/SshSessionService.cs`, `Services/Ssh/SshSession.cs` | SSH.NET; STA UI + `Task.Run` I/O | Production | Spike Ã¢â‚¬â€ russh client + session orch password path ([06-ssh-spike.md](06-ssh-spike.md), [16-session-orchestrator.md](16-session-orchestrator.md)); reconnect/backoff **policy** stub (`wormhole_ssh::reconnect` / Fake schedule) + orch **Fake** loop glue (`FakeSshReconnectGlue`); live UI/WebView2 rebind Pending | High |
| Sessions | Connecting progress stepper (phased overlay) | `ViewModels/Sessions/ConnectionProgress.cs`, `ConnectionProgressView.xaml(.cs)`, session VMs (`Progress.Begin` / `Fail` / tunnel `Detail`) | C# tunneled: VPN tunnel + Connect; direct Ã¢â€ â€™ plain spinner; failure overlay shows stepper only when `HasFailedStep` | Production | Lab Ã¢â‚¬â€ `wormhole-session::FakeConnectionProgressGlue` / `ConnectProgressPlan` (Resolve/Tunnel/Auth/Connect lab phases; cancel mid-flight reset fail-closed; `describe_tunnel_phase`; no secrets on `Debug`) ([16-session-orchestrator.md](16-session-orchestrator.md), [adversarial-ledger-connection-progress.md](adversarial-ledger-connection-progress.md)); GPUI overlay Pending | Low |
| SSH | xterm.js terminal in WebView2 | `Views/Sessions/SshTerminalView.xaml(.cs)`, `Interop/Terminal/TerminalBridge.cs`, `TerminalOutputPump.cs`, `TerminalInputWriter.cs`, `TerminalReplayBuffer.cs`, `Assets/web/` | Shared WebView2 env under `webview2\`; exact-replay on tab switch; process-exit recovery / rebind | Production | Lab Ã¢â‚¬â€ wire protocol + gate 5 / clipboard ([14-terminal-bridge.md](14-terminal-bridge.md), [01-surface-lab.md](01-surface-lab.md)); product tab host Pending | **High** |
| SSH | Auth: password, private key, keyboard-interactive paths | `Services/Ssh/SshAuthMethodsBuilder.cs`, `SshNetPrivateKeyInspector.cs` | Key files from DPAPI store | Production | Spike Ã¢â‚¬â€ password/key via `client` feature; agent + kbi wire auth `AuthNotImplemented`; KBI multi-prompt Fake channel always on ([06-ssh-spike.md](06-ssh-spike.md)) | High |
| SSH | Host key pin / mismatch prompt | `Services/Ssh/SshHostKeyValidator.cs`, `SshHostKeyMismatchException.cs`, profile `SshKnownHostFingerprint` | Persisted on accept for saved nodes; **not** for ephemeral Quick Connect | Production | Lab Ã¢â‚¬â€ `KnownHostsStore` + `verify_host_key_on_connect` (Accept/Reject/Prompt) + `resolve_host_key_prompted` / `FakeKnownHosts` ([06-ssh-spike.md](06-ssh-spike.md)); GPUI/WinUI dialog Pending | Med |
| SSH | Auto-sudo after connect | `Services/Ssh/SshAutoSudoDriver.cs`, migration `0008_ssh_auto_sudo.sql` | Uses captured password | Production | Lab Ã¢â‚¬â€ detector + `AutoSudoSessionGlue` / `FakeTerminalSession` stub; live shell Pending ([06-ssh-spike.md](06-ssh-spike.md)) | Med |
| SSH | SOCKS5 via tunnel | `SshSessionViewModel` + `Services/Tunneling/Socks5Client.cs` | When `TunnelEnabled` after inheritance + route prompt | Production | Lab Ã¢â‚¬â€ `select_ssh_connect_target` / FakeTunnelSocks route glue (Serial never; fail-closed missing SOCKS); dial CONNECT still stub ([06-ssh-spike.md](06-ssh-spike.md), [07-tunnels-mcp.md](07-tunnels-mcp.md), [adversarial-ledger-ssh-socks-route.md](adversarial-ledger-ssh-socks-route.md)) | High |
| SSH | Font / size / auto-copy selection | `Models/AppSettings.cs`, Settings General, terminal bridge | Cascadia Mono default | Production | Lab Ã¢â‚¬â€ settings VM fields + terminal apply glue (`settings_apply` / Fake; empty/whitespace font incl. NBSP / non-positive size fail-closed; auto-copy skips empty+oversize) ([17-tree-settings-vm.md](17-tree-settings-vm.md), [14-terminal-bridge.md](14-terminal-bridge.md)); live xterm options Pending | Low |
| SSH | MCP registration of live sessions | `Services/Mcp/McpSessionRegistry.cs` | Only already-open SSH tabs | Production | Lab Ã¢â‚¬â€ `FakeMcpSessionRegistry` register/unregister Connected ids ([07-tunnels-mcp.md](07-tunnels-mcp.md)); HTTP tool dispatch / live tab scan Pending | Med |

---

## SFTP (file transfer Ã¢â‚¬â€ not a session protocol)

| Area | Feature | Entry points (files) | Parity notes | WinUI | Rust | Risk |
|---|---|---|---|---|---|---|
| SFTP | Dual-pane file transfer dialog from connected SSH tab | `Views/Dialogs/FileTransferDialog.xaml(.cs)`, `ViewModels/Sessions/Transfer/*`, `Services/FileTransferDialogService.cs`, `Services/SftpService.cs`, `Services/Ssh/SftpSession.cs`, `Services/Sftp/FileTransferOrchestrator.cs` | `ProtocolType` has **no** SFTP (value 2 retired Ã¢â‚¬â€ migration `0009`); transfer only from SSH | Production | Lab Ã¢â‚¬â€ dialog glue (`ConnectedSshContext` Ã¢â€ â€™ SOCKS + cancel queue); dual-pane UI Pending ([11-sftp.md](11-sftp.md)) | High |
| SFTP | Background pre-warm of SFTP client | `SshSessionViewModel` (`_prewarmedSftpSession`, `BorrowTunnelForSftp`) | Separate SSH.NET SftpClient; can borrow tunnel lease | Production | Lab Ã¢â‚¬â€ Fake prewarm / borrow glue (`SftpPrewarmGlue` / `BorrowedShellTunnel`); live russh dial Pending ([11-sftp.md](11-sftp.md)) | High |
| SFTP | Upload/download/queue, conflict overlay, local quick paths, drag targets | `FileTransferOrchestrator.cs`, `TransferDropTarget.cs`, `LocalQuickPaths.cs`, `Views/Controls/FilePaneControl.xaml(.cs)`, `TransferQueueStrip.xaml(.cs)` | Local pane can shell-open paths via `Process.Start` | Production | Lab Ã¢â‚¬â€ serialized queue / single-flight cancel + progress callback + conflict overlay policy (`resolve_conflict_overlay` / Fake); GPUI overlays/drag / strip binding Pending ([11-sftp.md](11-sftp.md)) | Med |
| SFTP | SOCKS5 through same tunnel as SSH | `SftpService` / session tunnel borrow | Must not tear down shared tunnel early | Production | Spike Ã¢â‚¬â€ SOCKS target selection stub; live `russh-sftp` deferred ([11-sftp.md](11-sftp.md)) | High |
| UI | Legacy SFTP browser page exists | `Views/Pages/SftpBrowserPage.xaml(.cs)` | Prefer dialog path as primary shipped UX | Production | Pending (intentionally deprioritized) | Low |

---

## Serial

| Area | Feature | Entry points (files) | Parity notes | WinUI | Rust | Risk |
|---|---|---|---|---|---|---|
| Serial | Local COM terminal (`ProtocolType.Serial = 5`) | `Services/SerialSessionService.cs`, `Services/Serial/SerialSession.cs`, `ViewModels/Sessions/SerialSessionViewModel.cs`, migration `0013_serial_protocol.sql`, `Models/SerialSettings.cs` | Host = COM line (`COM1`, `\\.\COM10`, Ã¢â‚¬Â¦); `System.IO.Ports` | Production | Lab Ã¢â‚¬â€ `wormhole-serial` session + enumerate + `wormhole-ui::SerialPortPickerState` host glue + orch dispatch ([16-session-orchestrator.md](16-session-orchestrator.md), [20-connection-editor.md](20-connection-editor.md)); GPUI terminal / COM combo Pending | Med |
| Serial | PuTTY-style line settings | baud / data bits / stop bits / parity / flow (None, XON-XOFF, RTS-CTS, DSR-DTR) | Inherited like other node fields; defaults **9600 8N1, flow None** | Production | Lab Ã¢â‚¬â€ domain enums + `serial_settings_from_profile` + `SerialLineCombo` / `wormhole-ui` `serial_presets` editorÃ¢â€ â€node glue ([02-domain.md](02-domain.md), [20-connection-editor.md](20-connection-editor.md)); GPUI Serial tab Pending | Med |
| Serial | Reuses SSH xterm.js / `TerminalBridge` | `SshTerminalView` + `ITerminalSessionViewModel` | **No** credentials, **no** VPN routing | Production | Lab Ã¢â‚¬â€ shared `wormhole-terminal` traits ([14-terminal-bridge.md](14-terminal-bridge.md)) | Med |

---

## HTTP / HTTPS

| Area | Feature | Entry points (files) | Parity notes | WinUI | Rust | Risk |
|---|---|---|---|---|---|---|
| Web | Embedded WebView2 browser tabs (`Http=3`, `Https=4`) | `ViewModels/Sessions/HttpSessionViewModel.cs`, `Views/Sessions/WebBrowserView.xaml(.cs)` | Address = `host[:port]`; no path column; no Wormhole credentials | Production | Spike Ã¢â‚¬â€ `HttpConnectionTarget` + orch + Fake nav-resultÃ¢â€ â€™status glue; WebView2 host in `wormhole-surface-win` lab ([10-http.md](10-http.md), [16-session-orchestrator.md](16-session-orchestrator.md)) | High |
| Web | Ignore certificate errors (HTTPS) | `HttpIgnoreCertErrors`, migration `0011_http_ignore_cert_errors.sql`, `ServerCertificateErrorDetected=AlwaysAllow` | Needed for appliances; also for loopback-forwarder HTTPS; leaf-only (not folder-inherited) | Production | Lab Ã¢â‚¬â€ `HttpCertPolicy` + leafÃ¢â€ â€™AlwaysAllow **mapping** glue (COM subscribe not in lab create) ([10-http.md](10-http.md)) | Med |
| Web | Tunnel hybrid routing | SOCKS5 `--proxy-server=` when available; else `BindLocalForwarderAsync` | SOCKS preserves real hostname/SNI; loopback needs ignore-cert | Production | Lab Ã¢â‚¬â€ `select_http_tunnel_route` ([10-http.md](10-http.md)) | **High** |
| Web | Isolated / shared WebView2 profiles; startup wipe of non-extension web root | `Helpers/AppPaths.cs`, `App.xaml.cs` (`ClearWebBrowserUserData`), `Helpers/WebViewBrowserArguments.cs` | Argument-fingerprinted folders avoid `ERROR_INVALID_STATE` | Production | Spike Ã¢â‚¬â€ `profile_wipe` Fake glue (keyed fingerprint / shared vs isolated / wipe leaves Bitwarden) ([10-http.md](10-http.md)); live disk wipe / WebView2 env create Pending | High |
| Web | New-window handling / Bitwarden popups | `Helpers/WebViewNewWindowNavigation.cs`, `WebBrowserView.xaml.cs`, `Services/BitwardenBrowser/*` | No unmanaged popups; extension popups hosted in-app | Production | Lab Ã¢â‚¬â€ `new_window` Fake (`AllowInTab` / `HostPopup` / `Block`; Bitwarden chrome-extension HostPopup; empty/userinfo fail-closed) ([10-http.md](10-http.md)); live WebView2 NewWindowRequested Pending | High |

---

## VNC

| Area | Feature | Entry points (files) | Parity notes | WinUI | Rust | Risk |
|---|---|---|---|---|---|---|
| VNC | Embedded client (`ProtocolType.Vnc = 6`) | `Services/VncSessionService.cs`, `ViewModels/Sessions/VncSessionViewModel.cs`, `Views/Sessions/VncView.xaml(.cs)` | `Community.MarcusW.VncClient` | Production | Spike Ã¢â‚¬â€ protocol/auth types + connect target; live TCP deferred even with `engine` ([09-vnc.md](09-vnc.md)); session orch fails closed | High |
| VNC | Auth: none + classic VNC password only | `PasswordProviderAuthenticationHandler` in `VncSessionService` | Username/domain hidden/optional in UI; no advanced auth | Production | Lab Ã¢â‚¬â€ `auth_glue` (`select_vnc_auth` / `provide_vnc_auth_input` / `FakeVncPasswordProvider`; username/domain ignored; empty/`AuthCancelled` fail-closed; Debug redacts) ([09-vnc.md](09-vnc.md), [adversarial-ledger-vnc-password-auth.md](adversarial-ledger-vnc-password-auth.md)) | Med |
| VNC | Tunnel via local TCP forwarder | `BindLocalForwarderAsync` (same as RDP data path) | No RDP-specific gateway/cert rejects | Production | Lab Ã¢â‚¬â€ `select_vnc_connect_target` + tunnels forwarder ([09-vnc.md](09-vnc.md), [07-tunnels-mcp.md](07-tunnels-mcp.md)) | High |
| VNC | Input / framebuffer rendering | `VncView.xaml.cs` | WinUI render target + pointer/keyboard mapping | Production | Lab - `RawPixelBuffer` + `InputEventQueue` + `session_glue` (`FakeFramebufferDirtyNotify`; fail-closed when not Connected; apply errors skip dirty notify) + `input_resize_glue` (resize/disconnect drain+coalesce; OOB pointer drop; same-button move coalesce; keys FIFO; Fake counts only) + `clipboard_glue` (ClientCutText Ã¢â€ â€™ Fake send / ServerCutText Ã¢â€ â€™ local buffer; 1 MiB soft cap; empty fail-closed; Debug lengths only); orch still `UnsupportedProtocol`; GPUI surface Pending ([09-vnc.md](09-vnc.md)) | High |

---

## RDP

| Area | Feature | Entry points (files) | Parity notes | WinUI | Rust | Risk |
|---|---|---|---|---|---|---|
| RDP | Embedded ActiveX (`MsRdpClient*NotSafeForScripting`) | `Interop/Rdp/AxMsRdpClient9.cs`, `MsTscAxEventsSink.cs`, `RdpHostForm.cs`, `Services/RdpSessionService.cs`, `ViewModels/Sessions/RdpSessionViewModel.cs` | Prefers Client11Ã¢â€ â€™10Ã¢â€ â€™9 CLSID via registry probe; dynamic `GetOcx()`; events via `IConnectionPointContainer` | Production | Spike Ã¢â‚¬â€ `wormhole-surface-win` feature `rdp` OLE/CredSSP configure ([05-rdp-spike.md](05-rdp-spike.md)); session orch typed stub fails closed ([16-session-orchestrator.md](16-session-orchestrator.md)) | **High** |
| RDP | Owned top-level overlay (not SetParent child) | `Views/Sessions/RdpSurfaceHost.xaml(.cs)`, `Helpers/RdpOverlayCoordinator.cs`, `Helpers/Win32Interop.cs` | WinUI airspace: overlay owned via `GWLP_HWNDPARENT`, positioned with `MoveWindow`/`SetWindowPos` each layout tick; subclass owner for drag sync; hide during ContentDialogs | Production | Spike Ã¢â‚¬â€ owned-overlay broker path ([05-rdp-spike.md](05-rdp-spike.md), [native-surface-broker.md](native-surface-broker.md)) | **High** |
| RDP | Full RDP property surface (display, redirects, gateway, NLA/CredSSP, performance flags, dynamic resolution) | `RdpHostForm.cs`, `ConnectionNode` / `ConnectionProfile` RDP fields, migrations `0003_rdp_extras` Ã¢â‚¬Â¦ `0007_rdp_server_auth_warn_mapping` | Many optional IDispatch properties TrySet | Production | Spike Ã¢â‚¬â€ CredSSP / gateway / strict-auth / resolution + **display/redirect Fake glue** + **performance/bitmap Fake glue** (`RdpPerformanceFlagsGlue`) ([05-rdp-spike.md](05-rdp-spike.md)); audio / live OCX apply Pending | High |
| RDP | External `mstsc.exe` fallback | `RdpSessionViewModel` (`Process.Start("mstsc.exe")`), `Helpers/AzureAdCredentialDetector.cs`, migrations `0004`Ã¢â‚¬â€œ`0006` | AAD/WAM; crash-sentinel auto-flag (`Services/Rdp/RdpCrashSentinelService.cs`, `App.xaml.cs`) | Production | Lab Ã¢â‚¬â€ AAD detection + external tunnel Fake glue (`RdpAadExternalClientGlue` composes `RdpExternalMstscGlue`; scripted catalog; no live mstsc/WAM; [05-rdp-spike.md](05-rdp-spike.md), [adversarial-ledger-rdp-aad-external.md](adversarial-ledger-rdp-aad-external.md)); live launch Pending | High |
| RDP | Tunnel: `BindLocalForwarderAsync` Ã¢â€ â€™ connect OCX to `127.0.0.1:local` | `RdpSessionViewModel.PrepareConnectProfileAsync`, `Services/Tunneling/LocalTcpForwarder.cs` | **Rejected** combos with tunnel: external mstsc, RD Gateway, strict server auth | Production | Lab Ã¢â‚¬â€ `LocalForwarder` + tunnel policy helpers ([07-tunnels-mcp.md](07-tunnels-mcp.md), [05-rdp-spike.md](05-rdp-spike.md)) | **High** |
| RDP | Drive list / desktop size helpers | `Helpers/RdpDriveList.cs`, `RdpDesktopSizeResolver.cs`, `RdpScreenSizes.cs` | Win32 / display enumeration | Production | Lab Ã¢â‚¬â€ `RdpScreenSizes` in domain; connect-time resolve + drive parse in display/redirect Fake glue ([05-rdp-spike.md](05-rdp-spike.md)); live DriveCollection enum Pending | Med |
| RDP | STA requirement | WinForms `RdpHostForm` on UI/STA | Non-negotiable for OCX | Production | Spike Ã¢â‚¬â€ documented in RDP spike; host still lab-only ([05-rdp-spike.md](05-rdp-spike.md)) | High |

---

## Tunnels / VPN providers

| Area | Feature | Entry points (files) | Parity notes | WinUI | Rust | Risk |
|---|---|---|---|---|---|---|
| Tunnels UI | Tunnel configs page + editor + test dialog | `ViewModels/TunnelConfigsViewModel.cs`, `TunnelPickerViewModel.cs`, `TunnelTestDialogViewModel.cs`, `Views/Pages/TunnelConfigsPage.xaml`, `Views/Dialogs/TunnelDialog.xaml`, `TunnelTestDialog.xaml` | Metadata SQLite (`TunnelConfig`); secret DPAPI file | Production | Lab — `wormhole-ui::tunnel_configs_ui` list/filter/select + picker sentinels + `TunnelTestDialogVm` / `FakeTunnelTestLab` establish/probe Fake glue (`FakeTunnelConfigList` + optional `StorageTunnelConfigSource`; metadata only, no DPAPI; [07-tunnels-mcp.md](07-tunnels-mcp.md), [adversarial-ledger-tunnel-configs-ui.md](adversarial-ledger-tunnel-configs-ui.md), [adversarial-ledger-tunnel-test-dialog.md](adversarial-ledger-tunnel-test-dialog.md)); editor / GPUI Pending | High |
| Core | Ref-counted shared leases, coalesce establish, invalidate on `UpdatedAt` / Failed/Closed | `Services/Tunneling/TunnelManager.cs`, `BorrowedTunnelInstance.cs`, `SocksTunnelInstance.cs`, `ITunnelInstance.cs` | One OTP prompt for concurrent tabs | Production | Lab Ã¢â‚¬â€ `wormhole-tunnels::TunnelManager` ([07-tunnels-mcp.md](07-tunnels-mcp.md)) | **High** |
| Core | Route prompt (tunnel vs direct) | `TunnelRoutePrompter.cs`, setting `PromptBeforeTunnelConnect` | On by default | Production | Lab Ã¢â‚¬â€ `wormhole-session` `resolve_tunnel_route` / `FakeTunnelRoutePromptUi` (AllowTunnel / PreferDirect / Cancel; setting off auto-routes; Cancel fail-closed; [adversarial-ledger-tunnel-route-prompt.md](adversarial-ledger-tunnel-route-prompt.md)); WinUI dialog Pending | Med |
| Core | OTP / TLS trust prompts | `DialogOtpPromptService.cs`, `DialogTlsTrustPromptService.cs` | Shared across providers | Production | Spike — `OtpPrompt` Memory/Fake/Channel + UI glue `OtpPromptChannel`/`FakeOtpPromptUi` (no GPUI dialog; [adversarial-ledger-otp-ui.md](adversarial-ledger-otp-ui.md)); TLS trust Fake glue `TlsTrustPrompt` / channel + UI Fake ([adversarial-ledger-tls-trust-prompt.md](adversarial-ledger-tls-trust-prompt.md)); Stormshield ConfirmTrust wiring Pending ([07-tunnels-mcp.md](07-tunnels-mcp.md)) | Med |
| Core | Physical path / split-routing heuristics | `WindowsPhysicalNetworkPathService.cs` | Win32 `dnsapi` / `iphlpapi` P/Invokes | Production | Lab â€” `FakePhysicalNetworkPath` / `classify_split_route` (Direct/Physical/Unknown; empty host fail-closed; no live dnsapi/iphlpapi) ([07-tunnels-mcp.md](07-tunnels-mcp.md), [adversarial-ledger-physical-path.md](adversarial-ledger-physical-path.md)); Stormshield wiring Pending | High |
| WireGuard | Userspace sidecar | `Services/Tunneling/WireGuard/*`, `tools/wormhole-wgproxy`, `wormhole-wgproxy.exe` | SOCKS5 READY protocol | Production | Lab Ã¢â‚¬â€ sidecar spawn via `SidecarProcess` ([07-tunnels-mcp.md](07-tunnels-mcp.md)); product UX Pending | High |
| OpenVPN | Shared sidecar | `Services/Tunneling/OpenVpn/*`, `tools/wormhole-ovpnproxy`, `wormhole-ovpnproxy.exe` | Release requires real OpenVPN3 PE | Production | Lab Ã¢â‚¬â€ shared ovpn sidecar path + auth_glue ([07-tunnels-mcp.md](07-tunnels-mcp.md)) | High |
| Fortinet | Username/password + TOTP; SAML embedded WebView2 or external browser (loopback callback default **8020**) | `Services/Tunneling/Fortinet/*`, `wormhole-fortiproxy.exe` | Ephemeral `auth_id` / `SVPNCOOKIE` via stdin only; realm incompatible with external SSO; pin rejects embedded SSO | Production | Spike Ã¢â‚¬â€ sidecar spawn + `SamlAuthFlow` + `ChannelSamlAuthCallback` / UI glue `SamlPromptChannel`/`FakeSamlPromptUi` (no full WebView2/OS-browser UI; [adversarial-ledger-fortinet-saml-ui.md](adversarial-ledger-fortinet-saml-ui.md)) ([07-tunnels-mcp.md](07-tunnels-mcp.md)) | **High** |
| WatchGuard | Portal + OpenVPN data plane; profile DPAPI cache; SAML dialog | `Services/Tunneling/Watchguard/*` | OTP reuse / cache carefully ordered | Production | Spike Ã¢â‚¬â€ Firebox auth stub; not wired into establish ([07-tunnels-mcp.md](07-tunnels-mcp.md)) | High |
| Stormshield | Portal config download + OpenVPN; DPAPI cache; OTP reuse guard | `Services/Tunneling/Stormshield/*` | Single-use OTP must hit data plane, not HTTPS step on reconnect | Production | Spike Ã¢â‚¬â€ SNS auth stub + establish-path glue (`establish_stormshield` / `_sns`; portal/cache/SSO pending) ([07-tunnels-mcp.md](07-tunnels-mcp.md)) | High |
| Azure VPN | Entra ID OAuth (WebView2) + refresh-token DPAPI cache; OpenVPN with user `AzureAD` | `Services/Tunneling/AzureVpn/*` | Interactive popup; silent refresh | Production | Spike Ã¢â‚¬â€ `EntraTokenProvider` stub; interactive WebView2 popup not wired ([07-tunnels-mcp.md](07-tunnels-mcp.md)) | **High** |
| Cisco Secure Client | Aggregate-auth + CSTP via Go sidecar (not local Cisco UI) | `Services/Tunneling/CiscoSecureClient/*`, `tools/wormhole-ciscoproxy` | v1: user/pass + optional group + TOTP/secondary; **no** SAML/cert/CSD | Production | Spike Ã¢â‚¬â€ aggregate-auth typing stub; no STF/CSTP ([07-tunnels-mcp.md](07-tunnels-mcp.md)) | High |
| Routing matrix | SSH/SFTP Ã¢â€ â€™ SOCKS5; RDP/VNC Ã¢â€ â€™ local forwarder; HTTP Ã¢â€ â€™ SOCKS proxy args else forwarder; Serial Ã¢â€ â€™ never | Documented in README / `AGENTS.md` | Parity table for golden tests | Production | Lab Ã¢â‚¬â€ hooks in tunnels/http/ssh/sftp/session orch ([07-tunnels-mcp.md](07-tunnels-mcp.md), [16-session-orchestrator.md](16-session-orchestrator.md)); end-to-end product Pending | **High** |

---

## Bitwarden

| Area | Feature | Entry points (files) | Parity notes | WinUI | Rust | Risk |
|---|---|---|---|---|---|---|
| Vault | Optional CLI vault (`bw`) for credential passwords | `Services/Bitwarden/*`, Settings Extensions, migrations `0014`/`0015` | Session key **memory-only**; SQLite stores item refs + display cache only | Production | Spike Ã¢â‚¬â€ memory-only session stub; CLI spawn not wired ([04-secrets.md](04-secrets.md)) | High |
| Vault | Install/update CLI; login/unlock/sync | `BitwardenCliInstaller.cs`, `BitwardenCliVaultClient.cs`, `BitwardenCredentialSyncService.cs` | Official GitHub releases + pinned hashes in settings | Production | Lab — `BitwardenCliInstallGlue` / pin + SHA-256 Fake ([04-secrets.md](04-secrets.md), [adversarial-ledger-bitwarden-cli-pin.md](adversarial-ledger-bitwarden-cli-pin.md)); HTTP download + ZIP extract + GPUI settings wiring Pending | Med |
| Vault | Virtual read-only credentials in UI/pickers | `BitwardenCredentialCatalogService.cs`, `BitwardenVirtualCredentialIds.cs` | Resolve password at connect | Production | Lab — `BitwardenCredentialCatalogGlue` / Fake cache + stable virtual ids ([04-secrets.md](04-secrets.md), [adversarial-ledger-bitwarden-catalog.md](adversarial-ledger-bitwarden-catalog.md)); SQLite cache repo + GPUI picker wiring Pending | High |
| Browser | Official extension in HTTPS WebView2 profiles | `Services/BitwardenBrowser/*`, `WebBrowserView.xaml.cs` | Persistent profiles; shared storage DPAPI file; never wipe cookies/IDB; flush on shutdown/update | Production | Spike Ã¢â‚¬â€ profile folder/arg helpers in `wormhole-http` ([10-http.md](10-http.md)); extension host Pending | **High** |
| Browser | Manual ZIP/folder install stays pinned | Settings + installer services | Offline/enterprise | Production | Lab — `BitwardenExtensionInstallGlue` / `FakeZipArchive` + `FakeExtensionInstallFs` (zip-slip fail-closed; manual sources block auto-update; no untrusted zip IO in tests) ([04-secrets.md](04-secrets.md), [adversarial-ledger-bitwarden-zip-pin.md](adversarial-ledger-bitwarden-zip-pin.md)); GitHub download + GPUI settings wiring Pending | Med |
| Onboarding | Notice versioning | `BitwardenOnboardingNoticeService.cs`, settings schema | Soft UX only | Production | Lab â€” `BitwardenOnboardingNoticeGlue` / Fake settings store ([adversarial-ledger-bitwarden-onboarding.md](adversarial-ledger-bitwarden-onboarding.md)); GPUI dialog Pending | Low |

---

## MCP (AI agent control)

| Area | Feature | Entry points (files) | Parity notes | WinUI | Rust | Risk |
|---|---|---|---|---|---|---|
| MCP | Opt-in loopback Streamable HTTP MCP server | `Services/Mcp/McpServerHost.cs`, `McpSshTools.cs`, `McpSessionRegistry.cs`, Settings (MCP section), `ModelContextProtocol.AspNetCore` | Default `http://127.0.0.1:8765`; off by default | Production | Lab Ã¢â‚¬â€ `wormhole-mcp` `rmcp` Streamable HTTP + loopback bind ([07-tunnels-mcp.md](07-tunnels-mcp.md)); Settings toggle Pending | High |
| MCP | Bearer token in CredMgr (fixed guid) | `McpServerHost.TokenCredentialId` | Reveal/copy/regenerate in Settings; client config JSON helpers | Production | Lab Ã¢â‚¬â€ CredMgr/`MemoryTokenStore` + generate/authorize helpers ([07-tunnels-mcp.md](07-tunnels-mcp.md)) | High |
| MCP | Tools: `list_sessions`, `run_command`, `send_text`, `read_terminal` | `McpSshTools.cs` + SSH `ShellCommandRunner` | First action per session requires UI approval; **no** open-connection / read-creds tools | Production | Lab Ã¢â‚¬â€ tool defs + `SessionApprovalGate` / `FakeMcpToolApprovalGlue` (Approve/Deny/Cancel) + `FakeMcpSessionRegistry` ([07-tunnels-mcp.md](07-tunnels-mcp.md)); live SSH runner / HTTP dispatch wiring Pending | High |
| MCP | Clean shutdown vs WebView2 flush | `MainWindow.xaml.cs` (`PrepareForProcessExitAsync`) | WebView/Bitwarden flush must precede MCP stop on exit; ordering matters for Bitwarden DPAPI storage | Production | Lab Ã¢â‚¬â€ `FakeAppExitShutdownGlue` / `prepare_for_process_exit` step recorder ([07-tunnels-mcp.md](07-tunnels-mcp.md), [adversarial-ledger-mcp-shutdown-order.md](adversarial-ledger-mcp-shutdown-order.md)); GPUI shell wiring Pending | Med |

---

## Import / backup / update

| Area | Feature | Entry points (files) | Parity notes | WinUI | Rust | Risk |
|---|---|---|---|---|---|---|
| Import | mRemoteNG `confCons.xml` (SSH/RDP/VNC only) | `Services/MRemoteNg/*`, `ViewModels/MRemoteNgImportDialogViewModel.cs`, `Views/Dialogs/MRemoteNgImportDialog.xaml` | AES-GCM **16-byte nonce** via BouncyCastle (not `AesGcm`); passwords → CredMgr on commit; HTTP/HTTPS/Serial soft-skipped | Production | Lab — XML parse/plan + decrypt + apply stub + soft-skip `ImportSkipReport` + dialog VM Fake glue (`MRemoteNgImportDialogVm` / `FakeMRemoteNgImportPathUi` / `FakeMRemoteNgImportLab`; `wormhole-ui` feature `import`; no GPUI/COM picker) ([12-import.md](12-import.md), [adversarial-ledger-import-skip-report.md](adversarial-ledger-import-skip-report.md), [adversarial-ledger-import-dialog.md](adversarial-ledger-import-dialog.md)) | High |
| Backup | Export/import nodes, credentials, tunnels, Bitwarden **refs/cache**, passwords, keys, tunnel payloads | `Services/Backup/BackupService.cs`, `Models/Backup/BackupDocument.cs`, backup dialogs | Optional password → PBKDF2 (600k) + AES-GCM; caps file size / iterations; **excludes** Bitwarden passwords, WebView2 profiles, extension packages | Production | Lab — `FakeBackupLab` + `export_backup` / `import_backup` metadata + Fake secret round-trip; `StorageBackupSource`/`Sink` SQLite path; GPUI dialogs Pending ([12-import.md](12-import.md), [adversarial-ledger-backup.md](adversarial-ledger-backup.md)) | High |
| Update | GitHub release check / download / launch installer / changelog WebView | `Services/UpdateService.cs`, `ViewModels/UpdateViewModel.cs`, `Views/Controls/UpdateChangelogView.xaml(.cs)`, Settings Updates | Auto-check setting; skip version; prepare-for-install flushes Bitwarden WebViews | Production | Spike Ã¢â‚¬â€ Fake/NetworkStub checker + `check_now` notify glue (Available/None/Error); no live HTTP / installer UX ([13-update-logging.md](13-update-logging.md)) | Med |

---

## Settings & shell UI

| Area | Feature | Entry points (files) | Parity notes | WinUI | Rust | Risk |
|---|---|---|---|---|---|---|
| Settings | General: theme, confirm close, auto-copy, tunnel prompt, SSH font | `Views/Pages/SettingsPage.xaml`, `ViewModels/SettingsViewModel.cs`, `Services/AppSettingsService.cs` | `settings.json` schema v8 | Production | Lab Ã¢â‚¬â€ settings VM + `SettingsStore` ([17-tree-settings-vm.md](17-tree-settings-vm.md), [03-storage.md](03-storage.md)); GPUI page Pending | Med |
| Settings | Security: app lock / Hello / idle | (above) + `Services/Security/*` | | Production | Spike Ã¢â‚¬â€ secrets stubs + PIN/password verifier + idle-lock Fake glue ([04-secrets.md](04-secrets.md)); Settings Security UI Pending | High |
| Settings | Extensions: Bitwarden vault + browser | (above) | | Production | Lab — `BitwardenSettingsExtensionsGlue` / `BitwardenSettingsUiState` composes session + catalog + CLI pin + extension install + onboarding Fakes ([17-tree-settings-vm.md](17-tree-settings-vm.md), [adversarial-ledger-settings-bitwarden.md](adversarial-ledger-settings-bitwarden.md)); GPUI page Pending | High |
| Settings | Updates + MCP | (above) | | Production | Spike Ã¢â‚¬â€ update/MCP libraries Lab/Spike; Settings sections Pending | Med |
| Shell | Navigation: Sessions / Credentials / Tunnels / Settings | `MainWindow.xaml(.cs)`, `Services/NavigationService.cs`, `ViewModels/ShellViewModel.cs` | Custom title bar, Mica, sidebar width | Production | Spike Ã¢â‚¬â€ GPUI shell skeleton (`wormhole-ui` feature `gpui`) ([08-ui.md](08-ui.md)); not a product shell | Med |
| Shell | Tabbed sessions + close confirm | `ShellViewModel.Tabs`, `SessionsPage.xaml(.cs)` | | Production | Lab Ã¢â‚¬â€ session tab bar / tabs state ([17-tree-settings-vm.md](17-tree-settings-vm.md)); confirm UX Pending | Med |
| Shell | Multi-pane splits / drag-drop tiling | `ViewModels/Sessions/Layout/*`, `Views/Sessions/SessionLayoutHost.xaml(.cs)`, `SessionPaneHost`, `PaneSplitter`, `SessionDropOverlay` | Tabs stay in collection; layout is in-memory tiling | Production | Lab Ã¢â‚¬â€ pane layout tree + broker sink ([08-ui.md](08-ui.md), [01-surface-lab.md](01-surface-lab.md)); drag chrome Pending | **High** |
| Shell | Quick Connect (ephemeral full editor) | `ViewModels/QuickConnectViewModel.cs`, `Views/Controls/QuickConnectBar.xaml`, `DialogService.PromptQuickConnectAsync`, `Models/QuickConnectResult.cs` | All session protocols; `IsEphemeral=true`; transient password store | Production | Lab Ã¢â‚¬â€ pure QC state + session-orchestrator connect glue ([21-quick-connect.md](21-quick-connect.md), [16-session-orchestrator.md](16-session-orchestrator.md)); bar/dialog Pending | Med |
| Shell | Connection progress stepper | `Views/Sessions/ConnectionProgressView.xaml`, `ViewModels/Sessions/ConnectionProgress.cs` | Shared UX across protocols | Production | Lab â€” see Sessions row (`FakeConnectionProgressGlue`); GPUI overlay Pending | Low |
| Shell | Content dialog gating / RDP overlay suppress | `Services/ContentDialogGate.cs`, `ContentDialogTracker.cs`, `RdpOverlayCoordinator.cs` | Prevents overlay covering modals | Production | Spike Ã¢â‚¬â€ overlay hide notes in RDP spike; full dialog gate Pending ([05-rdp-spike.md](05-rdp-spike.md)) | High |
| Crash | Crash diagnostics / dumps | `Services/CrashDiagnosticsService.cs`, installer WER keys | | Production | Lab Ã¢â‚¬â€ secrets-free diagnostics report + soak **placeholders** ([19-diagnostics-soak.md](19-diagnostics-soak.md)); WER/dumps Pending | Med |

---

## Persistence / DI / logging (cross-cutting)

| Area | Feature | Entry points (files) | Parity notes | WinUI | Rust | Risk |
|---|---|---|---|---|---|---|
| DB | SQLite + Dapper + migrations | `Data/SqliteConnectionFactory.cs`, `MigrationRunner.cs`, `Data/Migrations/*.sql` | One connection per op; pinned native sqlite fetch | Production | Lab Ã¢â‚¬â€ rusqlite factory + embedded migrations + repos ([03-storage.md](03-storage.md)) | Med |
| DI | Composition root | `App.xaml.cs` | Resolves from `App.Current.Services` | Production | Lab Ã¢â‚¬â€ `wormhole-app` `AppServices` placeholder bag ([07-tunnels-mcp.md](07-tunnels-mcp.md)); not a shipping host | Med |
| Logs | Serilog file sink | `%LOCALAPPDATA%\Wormhole\logs\` | Retention setting | Production | Lab Ã¢â‚¬â€ tracing daily file + redaction ([13-update-logging.md](13-update-logging.md)) | Low |

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
