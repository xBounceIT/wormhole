# Phase 0 — Interop inventory

Baseline: `fc0337e0e8b4d6178ddf6c6838b1c45a8aecf60f`.  
Maps every significant **Win32 / COM / ActiveX / WebView2 / DPAPI / Credential Manager** touchpoint and why it matters for a future **NativeSurfaceBroker** (native HWND / browser / RDP surfaces) and **secrets** crates.

Paths are repo-relative from the worktree root.

**Rust ownership pointers** (crate paths + maturity) live in [§9](#9-rust-crate-ownership-honest). That table is the source of truth for “what exists in `rust/`” — it does **not** claim production parity with the WinUI app. WinUI remains production until Phase 7 cutover.

### Maturity labels (use these only)

| Label | Meaning |
|---|---|
| **LabOnly** | Exercised (or gated) via `surface-lab` / feature flags; needs hardware gate evidence; **not** product UI wiring. |
| **Spike** | Library / API shape landed (often with fakes); may run unit tests; **not** end-to-end product host. |
| **Unwired** | Types, stubs, or docs only — interactive OS UI, process spawn, COM subscription, or shell integration still missing. |
| **None** | No Rust crate/module yet for this touchpoint. |

Never treat LabOnly / Spike / Unwired as shipped feature parity.

---

## 1. Win32 windowing & input (NativeSurfaceBroker core)

| Touchpoint | Files | APIs / mechanism | Why it matters |
|---|---|---|---|
| Central P/Invoke surface | `Helpers/Win32Interop.cs` | `user32`: `SetParent`, `GetDpiForWindow`, `GetSystemMetrics`, `MoveWindow`, `SendMessage`, `ShowWindow`, `Get/SetWindowLong(Ptr)`, `SetWindowPos`, `RedrawWindow`, `SetFocus`, `GetWindowRect`, `ClientToScreen`, `GetLastInputInfo`; `kernel32`: `GetTickCount64`; `comctl32`: `SetWindowSubclass` / `RemoveWindowSubclass` / `DefSubclassProc` | Single catalog for RDP overlay positioning, DPI, idle lock, focus. Broker must expose equivalent ops without leaking HWND lifetime bugs (subclass proc must stay rooted). |
| RDP owned overlay host | `Views/Sessions/RdpSurfaceHost.xaml(.cs)`, `Interop/Rdp/RdpHostForm.cs`, `Services/RdpSessionService.cs`, `Helpers/RdpOverlayCoordinator.cs` | Top-level **owned** window (`GWLP_HWNDPARENT`), **not** `WS_CHILD`/`SetParent` into WinUI (airspace paints behind XAML). Layout ticks drive screen-coordinate `MoveWindow`/`SetWindowPos`; owner subclass syncs drag; `ShowWindow` hide on minimize / dialog suppress | Highest-risk UI interop. GPUI must either keep a Win32 overlay compositor or replace RDP embedding entirely. `SetParent` remains declared/commented as the **rejected** path. |
| RDP AxHost HWND | `RdpHostForm.cs` | WinForms Form + AxHost; force handle creation before configure; child Ax `MoveWindow` inside form | STA + message pump requirements. |
| DPI / metrics | `Win32Interop.GetDpiForWindow`, `GetSystemMetrics`; RDP size helpers | Per-monitor V2 manifest (`app.manifest`) | Overlay geometry must track XamlRoot / AppWindow changes. |
| Idle / remote session | `GetLastInputInfo` + `GetTickCount64` (app lock); `SM_REMOTESESSION` via `Services/Security/RemoteDesktopSessionDetector.cs` | App inactivity lock; disable Windows Hello in RDP sessions | Secrets/UI unlock behavior depends on these signals. |
| Network path probing | `Services/Tunneling/WindowsPhysicalNetworkPathService.cs` | `DllImport` `dnsapi.dll`, `iphlpapi.dll` | Tunnel “direct vs VPN” heuristics; not a surface broker item but OS-specific. |
| Clipboard | `Helpers/ClipboardHelper.cs` | WinRT `Clipboard.SetContent` / `Flush` (COMException-tolerant) | Terminal auto-copy / MCP copy; never log payload (may be secret). |
| HWND helpers | `Helpers/HwndExtensions.cs` | Window handle acquisition for Hello / overlays | Bridge WinUI → HWND for UserConsentVerifier. |

---

## 2. COM / ActiveX — RDP (NativeSurfaceBroker)

| Touchpoint | Files | APIs / mechanism | Why it matters |
|---|---|---|---|
| MsRdp ActiveX class selection | `Interop/Rdp/AxMsRdpClient9.cs` | Registry probe `HKCR\CLSID\{…}` for Client11 / 10 / 9 NotSafeForScripting; `AxHost` subclass | Must activate newest registered `mstscax` class; fallback CLSID `8B918B82-7985-4C24-89DF-C33AD2BBFBCD` (v9). |
| Property access | `RdpHostForm.cs` via `GetOcx()` + `dynamic` | Large optional IDispatch surface (CredSSP, gateway, redirects, SmartSizing, `UpdateSessionDisplaySettings`, performance flags, …) | Hand-rolled — no AxImp. Broker needs a stable RDP capability layer; missing props are soft-fail (`TrySetOptional`). |
| Events | `Interop/Rdp/MsTscAxEventsSink.cs` | `[ComImport]` / `[Guid]` `IMsTscAxEvents`; `IConnectionPointContainer.Advise` | Connection/login/disconnect/fatal error sink; DISPID order is ABI. |
| External client | `ViewModels/Sessions/RdpSessionViewModel.cs` | `Process.Start("mstsc.exe", /v:host:port)` | Escape hatch for AAD/WAM; incompatible with tunnel forwarder. Process lifetime tracked but not killed on tab close. |
| Crash sentinel | `Services/Rdp/RdpCrashSentinelService.cs`, `App.xaml.cs` | Persist mid-handshake marker; on next launch auto-set `RdpUseExternalClient` | Mitigates SEH `0xC06D007F` from WAM delay-load in unpackaged process. |
| AAD detection | `Helpers/AzureAdCredentialDetector.cs` + migrations `0005`/`0006` | Username patterns → external client | Behavioral parity for Azure AD targets. |

**NativeSurfaceBroker takeaway:** RDP is the hardest surface — WinForms OCX in an owned Win32 overlay synchronized to a GPUI/WinUI layout slot, plus optional out-of-process `mstsc.exe`.

---

## 3. WebView2 surfaces (NativeSurfaceBroker)

All environments should live under `%LOCALAPPDATA%\Wormhole\…` (not beside Program Files). Argument-fingerprinted subfolders: `Helpers/WebViewBrowserArguments.cs` + `Helpers/AppPaths.cs`.

| Surface | Files | User-data root (concept) | Special args / behavior | Why it matters |
|---|---|---|---|---|
| SSH / Serial terminal | `Views/Sessions/SshTerminalView.xaml(.cs)`, `Interop/Terminal/TerminalBridge.cs` (+ pump/input/replay/focus/recovery) | `webview2\` (shared env) | Host resource access Allow; xterm.js from `Assets/web`; WebMessage bridge | Terminal I/O path; process exit → replace control; exact-replay across tab switches |
| HTTP/HTTPS browser | `Views/Sessions/WebBrowserView.xaml(.cs)`, `HttpSessionViewModel.cs` | `webview2-web\` (wiped at startup except Bitwarden path) | Optional `--proxy-server=socks5://…`; ignore-cert policy; isolated per-tab folders | Tunnel hybrid routing; cert policy keyed into env identity |
| Bitwarden HTTPS profiles | `Services/BitwardenBrowser/*`, `WebBrowserView` | `bitwarden-browser-webview2\` + `bitwarden-browser-storage.dpapi` | Extension install; shared storage sync; flush/close before shutdown/update | Persistent IdP/extension state; secrets-adjacent |
| Fortinet SAML embedded | `Services/Tunneling/Fortinet/FortinetSamlAuthService.cs` | `fortinet-saml-webview2\` | Clears SVPNCOOKIE around auth; gateway-origin cert bypass option; rejects cert-pin configs | Ephemeral cookie → sidecar stdin only |
| Fortinet SAML external | same + `Process.Start` browser | Loopback callback (default port **8020**) | Reserves port before launch; `auth_id` | OS browser + local HTTP listener |
| WatchGuard SAML | `Services/Tunneling/Watchguard/DialogWatchguardSamlAuthService.cs` | `watchguard-saml-webview2\` | Embedded auth dialog | |
| Azure VPN Entra | `Services/Tunneling/AzureVpn/DialogAzureVpnAuthService.cs`, `AzureVpnOAuthClient.cs` | `azurevpn-webview2\` | OAuth code flow; refresh tokens DPAPI-cached | Interactive Microsoft login |
| Update changelog | `Views/Controls/UpdateChangelogView.xaml(.cs)` | `update-changelog-webview2\` | Renders Markdown→HTML | Low risk |
| New-window policy | `Helpers/WebViewNewWindowNavigation.cs` | — | Redirect into existing session / suppress unmanaged popups | Prevents orphan Edge windows without proxy/certs |

**NativeSurfaceBroker takeaway:** Many concurrent WebView2 environments with **different** browser args (proxy/cert) must not share a user-data folder. Broker should centralize env creation, keyed folders, and ordered teardown (Bitwarden flush before exit).

---

## 4. Process / sidecar spawning (adjacent to broker)

| Component | Files | Binary | Notes |
|---|---|---|---|
| WireGuard | `Services/Tunneling/WireGuard/*` | `wormhole-wgproxy.exe` | Userspace; prints READY + SOCKS5 |
| OpenVPN family | `Services/Tunneling/OpenVpn/*` (+ WatchGuard/Stormshield/Azure builders) | `wormhole-ovpnproxy.exe` | Secrets via config/stdin patterns — never log |
| Fortinet | `Services/Tunneling/Fortinet/*` | `wormhole-fortiproxy.exe` | SAML token via stdin |
| Cisco | `Services/Tunneling/CiscoSecureClient/*` | `wormhole-ciscoproxy.exe` | AnyConnect protocol; not Cisco UI |
| Local TCP forwarder | `Services/Tunneling/LocalTcpForwarder.cs`, `SocksTunnelInstance.BindLocalForwarderAsync` | — | `127.0.0.1` listener → tunnel dial for RDP/VNC/HTTP fallback |
| SOCKS client | `Services/Tunneling/Socks5Client.cs` | — | SSH/SFTP path |
| Bitwarden CLI | `Services/Bitwarden/BitwardenProcessRunner.cs` | `bw` under `tools\bitwarden-cli` | Session key in memory |
| Updates / shell open | `UpdateService`, Settings, FilePane | `Process.Start` | Installer launch, open logs/folder, open URLs |

---

## 5. Secrets crate inventory (CredMgr + DPAPI + crypto)

### 5.1 Windows Credential Manager

| Key pattern | Files | Payload | Notes |
|---|---|---|---|
| `Wormhole:<credentialGuid>` | `Services/CredentialService.cs` | Saved credential passwords | `CredentialPersistence.LocalMachine`; Meziantou wrapper |
| `Wormhole:<nodeGuid>` | Inline password path (`UseInlinePassword`) via same `StorePasswordAsync` | Per-connection SSH/RDP password | Flag in SQLite only; secret in CredMgr |
| `Wormhole:a7f3c1e2-9b6d-4e8a-bf21-7c0d2e5a4b91` | `Services/Mcp/McpServerHost.cs` | MCP bearer token | Fixed guid; regenerate from Settings |
| Import / backup restore | `MRemoteNgImportService.cs`, `BackupService.cs` | Writes passwords through `ICredentialService` | Must stay on same key scheme for migration |

### 5.2 DPAPI files (`ProtectedData`, CurrentUser)

| Path pattern | Files | Entropy | Payload |
|---|---|---|---|
| `keys\<credId:N>.dpapi` | `CredentialService` | none (`optionalEntropy: null`) | SSH private key bytes |
| `tunnels\<tunnelId:N>.dpapi` | `CredentialService` | none | Provider secret config blob |
| `app-auth.dpapi` | `DpapiAppAuthenticationDataProtector.cs` | UTF-8 `Wormhole.AppAuthentication.v1` | App unlock verifier material |
| `bitwarden-browser-storage.dpapi` | `BitwardenBrowserSharedStorage.cs` | dedicated entropy constant in that type | Cross-profile extension shared storage |
| `stormshield-cache\…` | `StormshieldConfigCache.cs` | per-`tunnelConfigId` entropy | Cached OpenVPN profile JSON |
| `watchguard-cache\…` | `WatchguardProfileCache.cs` | per-tunnel entropy | Cached OpenVPN profile |
| `azurevpn-cache\…` | `AzureVpnTokenCache.cs` | per-tunnel entropy | Entra **refresh tokens** |

### 5.3 Non-DPAPI secret crypto

| Mechanism | Files | Purpose |
|---|---|---|
| Backup PBKDF2 + AES-GCM | `Services/Backup/BackupService.cs`, `Models/Backup/BackupDocument.cs` | Password-sealed export (600k iterations default; max accepted 5M; 12-byte nonce) |
| mRemoteNG AES-GCM | `Services/MRemoteNg/MRemoteNgCrypto.cs` | **16-byte nonce** — BouncyCastle required |
| Bitwarden CLI session | `BitwardenCliVaultClient` / session service | Memory-only session key; never SQLite/backup |
| Fortinet SAML cookies / auth_id | `FortinetSamlAuthService` | Ephemeral; stdin to sidecar; not persisted |
| Transient session passwords | `ITransientSessionCredentialStore` | In-memory for Quick Connect / prompts; Rust: `wormhole-secrets-win::transient_session` (`Memory`/`Fake`; never SQLite/CredMgr/DPAPI) |

### 5.4 Explicit non-secrets (safe to copy in fixtures metadata)

- SQLite: nodes, credential **metadata**, tunnel **rows**, Bitwarden item **references/cache** (no passwords).
- `settings.json` (MCP flag/port only — token is CredMgr).
- WebView2 profile directories (contain cookies — treat as secret **data**, not for golden fixture commits).

---

## 6. Other OS / platform APIs

| Area | Files | Mechanism | Notes |
|---|---|---|---|
| Windows Hello | `Services/Security/WindowsHelloService.cs` | `Windows.Security.Credentials.UI.UserConsentVerifier` | Needs owner HWND; blocked when remote session |
| Serial ports | `Services/SerialSessionService.cs` | `System.IO.Ports.SerialPort` | Local device ACL; not VPN |
| MCP HTTP | `McpServerHost.cs` | Kestrel loopback + MCP SDK | AspNetCore framework reference; installer self-contained |
| VNC library | `VncSessionService.cs` | Managed RFB client | Tunnel only via local forwarder |
| SSH/SFTP | SSH.NET | Managed + optional SOCKS stream | |

---

## 7. Mapping to migration crates (design guidance)

Suggested responsibilities (still the design target — see [§9](#9-rust-crate-ownership-honest) for what actually exists):

### NativeSurfaceBroker

1. **RdpSurface** — activate OCX or substitute; own overlay HWND; layout sync; dialog suppression; external mstsc handoff.
2. **WebViewSurface** — create keyed environments; terminal bridge protocol; browser proxy/cert knobs; SAML/OAuth popups; Bitwarden extension lifecycle.
3. **TunnelIo** — spawn sidecars; SOCKS5; `BindLocalForwarder`; no UI.
4. **Win32Util** — DPI, subclass, idle, remote-session, focus.

### Secrets crate

1. CredMgr password API with `Wormhole:` prefix compatibility.
2. DPAPI protect/unprotect with **exact** entropy rules per blob type (null vs named vs per-tunnel).
3. Backup seal/unseal + mRemoteNG decrypt (nonce sizes).
4. Never log; redaction hooks; migration importers that preserve key IDs.

### Compatibility constraint

A Rust rewrite that wants to open existing user profiles **must** read the same CredMgr names and DPAPI blobs (CurrentUser scope) or ship a one-shot migrator while the Windows user profile is unlocked.

---

## 8. Stale doc note

`AGENTS.md` / `CLAUDE.md` still describe RDP as “reparented via `SetParent`”. Current code uses an **owned top-level overlay** and documents SetParent as the broken airspace approach (`RdpSessionService`, `RdpHostForm`, `RdpSurfaceHost`). Prefer this inventory over the older wording when designing NativeSurfaceBroker.

---

## 9. Rust crate ownership (honest)

Snapshot of where each major interop area lives under `rust/crates/`.  
**None of this replaces WinUI production.** Status labels: [Maturity labels](#maturity-labels-use-these-only). Related: [native-surface-broker.md](native-surface-broker.md), [01-surface-lab.md](01-surface-lab.md), [04-secrets.md](04-secrets.md), [07-tunnels-mcp.md](07-tunnels-mcp.md), [gate-checklist.md](gate-checklist.md).

### 9.1 Native surface / Win32 / COM / WebView2

| Interop area (§) | Rust crate / path | Status | Notes (honest) |
|---|---|---|---|
| NativeSurfaceBroker skeleton | `wormhole-surface-win` (`broker.rs`, `kinds.rs`, `bounds.rs`, `zorder.rs`) | **Spike** | Stub broker + layout/z-order types; default build has **no** WebView2/COM graph. |
| Lab gate host | `surface-lab` (`gates/gate01`–`gate08`, optional `gpui_host`) | **LabOnly** | Gate binary only; hardware sign-off still required ([gate-checklist.md](gate-checklist.md)). |
| Win32 focus / SetFocus | `wormhole-surface-win/src/focus/` | **Spike** / **LabOnly** | `FocusBroker` + `Win32FocusOps`; gate 7 lab path. Not full GPUI↔product focus chrome. |
| Pane layout → broker bounds | `wormhole-surface-win` feature `pane-layout` | **Spike** / **LabOnly** | Maps `wormhole-ui` pane ticks → `update_bounds`; lab smoke only. |
| WebView2 child HWND | `wormhole-surface-win/src/webview/` (feature `webview`) | **LabOnly** | wry 0.56 `ChildWebViewHost`; unique UDF; gates 3–5. Cert-policy **adapter only** — COM `ServerCertificateErrorDetected` **not** subscribed in create/lab. |
| xterm.js / terminal bridge wire | `wormhole-terminal` + lab gate 5 + `webview` assets helpers | **Spike** / **LabOnly** | Message types / backpressure / clipboard helpers; lab hosts Assets/web. Not a shipping SSH tab. |
| Host clipboard (Win32) | `wormhole-terminal` feature `clipboard-win` | **Spike** | Optional Win32 clipboard; fakes for tests. |
| RDP owned overlay / ActiveX | `wormhole-surface-win/src/rdp/` (feature `rdp`) | **LabOnly** / **Spike** | Owned overlay + OLE in-place + CredSSP configure + CLSID probe (gate 6). Event sink / connect paths remain spike-level; **not** product session chrome. |
| RDP crash sentinel / resolution debounce | `wormhole-surface-win/src/rdp/{sentinel,resolution,host_bounds}.rs` | **Spike** | Compile without `mstscax`; file/layout helpers only. |
| RDP external `mstsc.exe` | — | **None** / **Unwired** | C# escape hatch not ported as a product host path. |
| RDP overlay dialog suppress / owner subclass | partial via overlay host under `rdp` | **LabOnly** | Lab/spike surface; full `RdpOverlayCoordinator` parity **Unwired**. |
| DPI / idle (`GetLastInputInfo`) / window subclass catalog | — (focus ops only today) | **Unwired** / **None** | No full `Win32Interop.cs` port; idle lock + subclass sync not a dedicated crate. |
| Network path probing (`dnsapi` / `iphlpapi`) | — | **None** | Still C#-only. |

### 9.2 Secrets (CredMgr / DPAPI / Hello)

| Interop area (§) | Rust crate / path | Status | Notes (honest) |
|---|---|---|---|
| Credential Manager passwords | `wormhole-secrets-win` (`cred_mgr.rs`) | **Spike** | `Wormhole:<guid>` + 2560 UTF-16 guard + `FakePasswordStore`. Library API — not UI-wired. |
| Keys / tunnel DPAPI files | `wormhole-secrets-win` (`key_tunnel.rs`, `dpapi.rs`, `paths.rs`) | **Spike** | Null-entropy key/tunnel blobs; path confinement. |
| Named / per-tunnel entropy | `wormhole-secrets-win` (`entropy.rs`) | **Spike** | App-auth, Bitwarden shared storage, Azure/WG/Stormshield cache entropy constants. |
| App-auth store | `wormhole-secrets-win` (`app_auth.rs`) | **Spike** | `app-auth.dpapi` protect/unlock helpers. |
| Windows Hello / remote-session gate | `wormhole-secrets-win` (`hello.rs`, `win32.rs`) | **Unwired** (interactive) / **Spike** (stubs) | `AvailabilityProbe` / `HelloPrompt` stubs + `SM_REMOTESESSION` probe. WinRT `UserConsentVerifier` = `WINRT_HELLO_GAP` — **not wired**. |
| Bitwarden CLI session | `wormhole-secrets-win` (`bitwarden_session.rs`) | **Unwired** (spawn) / **Spike** (stubs) | Memory-only session stubs; `bw` process spawn **not wired** (`BITWARDEN_CLI_SESSION_GAP`). |
| Bitwarden browser WebView2 + DPAPI shared storage | — (entropy constant only in secrets-win) | **Unwired** / **None** | No Rust Bitwarden extension host / profile sync. |
| Redaction helpers | `wormhole-secrets-win` (`redact.rs`) | **Spike** | Logging hygiene only. |
| MCP bearer in CredMgr | `wormhole-mcp` + optional `secrets` feature → CredMgr token store | **Spike** | Loopback host / token helpers; not product Settings UI. |
| Backup PBKDF2 + AES-GCM | `wormhole-import` (`backup.rs`, envelope inspect) | **Spike** | Envelope / inspect path; not a full restore UI. |
| mRemoteNG AES-GCM (16-byte nonce) | `wormhole-import` (`crypto.rs`, `mremoteng.rs`) | **Spike** | XML plan + decrypt; HTTP/HTTPS/Serial soft-skip parity docs — not tree UI import. |

### 9.3 Tunnels / sidecars / forwarders

| Interop area (§) | Rust crate / path | Status | Notes (honest) |
|---|---|---|---|
| TunnelManager lease pool | `wormhole-tunnels` (`manager.rs`, `lease.rs`) | **Spike** | Ref-counted establish/coalesce mirror; unit/fake coverage. |
| Sidecar spawn + READY/SOCKS | `wormhole-tunnels` (`sidecar/`, `providers/spawn.rs`) | **Spike** | Locates/spawns Go sidecars when present; lab/tests may use fakes. Not product VPN UI. |
| WireGuard / OpenVPN / Fortinet / Cisco providers | `wormhole-tunnels/src/providers/` | **Spike** | Provider shells + sidecar config; real auth UX often stubbed. |
| SOCKS5 client + local TCP forwarder | `wormhole-tunnels` (`socks5.rs`, `forwarder.rs`) | **Spike** | Library path for SSH/SFTP/RDP-VNC-HTTP fallback. |
| Fortinet SAML (WebView2 / external browser) | `wormhole-tunnels/.../fortinet/saml.rs` | **Unwired** | Path types + `StubSamlAuthCallback` → `NotImplemented`; **no** WebView2 dialog, OS browser, or loopback listener. |
| WatchGuard / Stormshield / Azure Entra auth glue | `wormhole-tunnels/.../auth_glue/`, `watchguard/`, etc. | **Unwired** / **Spike** | Materials/cache/OTP/Entra **stubs & fakes**; interactive WebView2 OAuth / SAML dialogs **not** ported. |
| Physical network path service | — | **None** | C#-only. |

### 9.4 Adjacent protocols (not HWND broker, but OS-touching)

| Interop area (§) | Rust crate / path | Status | Notes (honest) |
|---|---|---|---|
| Serial ports | `wormhole-serial` + `wormhole-ui::SerialPortPickerState` | **Spike** | Enumerate + session I/O library; pure host-field picker glue (no GPUI chrome). |
| SSH / known hosts / agent stubs | `wormhole-ssh` | **Spike** | russh-oriented library; agent probe stubs. |
| SFTP queue / transport | `wormhole-sftp` | **Spike** | Serialized ops + fakes; VPN SOCKS path library-level. |
| HTTP target / cert / route / nav-report | `wormhole-http` | **Spike** | Pure target/route/cert + Fake nav-result→status glue — **no** WebView2 ownership. |
| VNC / RFB | `wormhole-vnc` | **Spike** | Framebuffer/input spike; tunnel via forwarder stubs. |
| Session orchestrator | `wormhole-session` | **Spike** | Connects protocol stubs + tunnel lease; not GPUI product shell. |
| MCP loopback HTTP | `wormhole-mcp` | **Spike** | Bind/token/approval; optional `rmcp` feature. |
| Diagnostics / WebView2 runtime probe | `wormhole-diagnostics` + `surface-lab --diagnostics` | **LabOnly** / **Spike** | Support snapshot helpers; not a shipped Help UI. |

### 9.5 Quick “where do I look?” index

| Concern | Start here |
|---|---|
| HWND broker / RDP / WebView2 | `rust/crates/wormhole-surface-win` + `rust/crates/surface-lab` |
| CredMgr / DPAPI / Hello stubs | `rust/crates/wormhole-secrets-win` |
| Sidecars / SOCKS / forwarder | `rust/crates/wormhole-tunnels` |
| xterm wire protocol | `rust/crates/wormhole-terminal` |
| Import / backup crypto | `rust/crates/wormhole-import` |
| Design analysis (C# → broker) | [native-surface-broker.md](native-surface-broker.md) |
