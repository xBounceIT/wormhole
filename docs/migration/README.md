# Wormhole migration: WinUI 3/C# → Rust/GPUI

**Status:** WinUI 3/C# remains production. Parallel Rust lab is active (`rust/` — ~20 crates: `surface-lab`, domain/storage/secrets, protocols, tunnels/MCP, session/UI stubs, diagnostics, etc.) with many adversarial ledgers closed. Surface-lab gates 1–8 are **LabOnly** only — see [gate-evidence-log.md](gate-evidence-log.md); none are `HardwarePass`, and there is **no cutover**.  
**Baseline:** `fc0337e` (app 0.9.0) — see `00-baseline.md`  
**Rule:** do not cut over production until surface-lab gates 3–8 pass on real x64 and ARM64 hardware (`HardwarePass` in the evidence log).

## Documents

| Doc | Owner focus |
|---|---|
| [00-baseline.md](00-baseline.md) | Tag, commit, packaging |
| [feature-matrix.md](feature-matrix.md) | Shipped feature parity matrix |
| [interop-inventory.md](interop-inventory.md) | Win32 / COM / WebView2 / secrets touchpoints + Rust crate ownership (LabOnly / Spike / Unwired) |
| [native-surface-broker.md](native-surface-broker.md) | C# hosting → Rust broker design |
| [deps-pins.md](deps-pins.md) | GPUI / WebView2 / `windows` crate pins |
| [06-ssh-spike.md](06-ssh-spike.md) | russh choice + SOCKS5 route select + dial hook points |
| [01-surface-lab.md](01-surface-lab.md) | How to run the lab + gate map |
| [02-domain.md](02-domain.md) | `wormhole-domain` C#→Rust map + inheritance parity |
| [03-storage.md](03-storage.md) | SQLite / rusqlite + embedded migrations |
| [04-secrets.md](04-secrets.md) | CredMgr + DPAPI + entropy (`wormhole-secrets-win`) |
| [07-tunnels-mcp.md](07-tunnels-mcp.md) | TunnelManager lease pool + MCP host stubs |
| [08-focus-a11y.md](08-focus-a11y.md) | FocusBroker + AccessKit / UIA gaps (gates 7–8) |
| [08-ui.md](08-ui.md) | GPUI shell skeleton (`wormhole-ui`) |
| [09-vnc.md](09-vnc.md) | VNC/RFB spike + `vnc-rs` audit |
| [10-http.md](10-http.md) | `HttpConnectionTarget` Rust port |
| [11-sftp.md](11-sftp.md) | Serialized SFTP ops + transfer queue + dialog glue (`wormhole-sftp`) |
| [12-import.md](12-import.md) | mRemoteNG XML import spike + backup envelope (`wormhole-import`) |
| [13-update-logging.md](13-update-logging.md) | Update check stubs + tracing daily file / redaction |
| [14-terminal-bridge.md](14-terminal-bridge.md) | xterm.js wire protocol + gate 5 Assets/web host |
| [15-cutover.md](15-cutover.md) | Inno parallel install, DB/secrets checklist, rollback, gate reminder |
| [17-tree-settings-vm.md](17-tree-settings-vm.md) | Connection-tree + settings view-models (`wormhole-ui`) |
| [adversarial-ledger-tree-settings-vm.md](adversarial-ledger-tree-settings-vm.md) | Connection-tree + settings VM review closed |
| [adversarial-ledger-tree-filter.md](adversarial-ledger-tree-filter.md) | Tree filter/search id glue (`visible_connection_ids` / host match) review closed |
| [adversarial-ledger-tree-open-session.md](adversarial-ledger-tree-open-session.md) | Tree Open → session connect glue review closed |
| [adversarial-ledger-tree-reparent.md](adversarial-ledger-tree-reparent.md) | Tree reparent / drag validation glue review closed |
| [adversarial-ledger-tree-duplicate.md](adversarial-ledger-tree-duplicate.md) | Tree duplicate connection glue review closed |
| [adversarial-ledger-settings-apply.md](adversarial-ledger-settings-apply.md) | SettingsViewModel → StorageSettingsStore stage/apply glue review closed |
| [16-session-orchestrator.md](16-session-orchestrator.md) | Session orchestrator (`wormhole-session`) Serial/SSH/HTTP + tunnel lease |
| [18-rust-installer.md](18-rust-installer.md) | Rust `Build-Rust-Artifacts.ps1` + parallel Inno channel spike (WinUI untouched) |
| [19-diagnostics-soak.md](19-diagnostics-soak.md) | Support diagnostics report + soak/benchmark harness stubs |
| [20-connection-editor.md](20-connection-editor.md) | Connection editor dialog state machine (`wormhole-ui`, no GPUI) |
| [adversarial-ledger-editor-save.md](adversarial-ledger-editor-save.md) | Connection editor → storage persist glue review closed |
| [21-quick-connect.md](21-quick-connect.md) | Quick Connect pure state / validation (`wormhole-ui`) |
| [adversarial-ledger-connection-editor.md](adversarial-ledger-connection-editor.md) | ConnectionEditorState review closed (no GPUI) |
| [adversarial-ledger-credential-picker.md](adversarial-ledger-credential-picker.md) | Credential picker search glue (`filter_credential_profiles` / Fake / SearchVm) review closed |
| [gate-checklist.md](gate-checklist.md) | Executable pass/fail for gates 1–8 |
| [gate-evidence-log.md](gate-evidence-log.md) | LabOnly vs HardwarePass evidence stubs (lab ≠ hardware) |
| [toolchain.md](toolchain.md) | Existing Rust PATH/versions for agents |
| [adversarial-review-policy.md](adversarial-review-policy.md) | Run adversarial-review-fix after each subagent |
| [adversarial-ledger-hello-cutover.md](adversarial-ledger-hello-cutover.md) | Hello / app-auth / Bitwarden browser / cutover review closed |
| [adversarial-ledger-bitwarden-session.md](adversarial-ledger-bitwarden-session.md) | Bitwarden CLI session stub (`StubBitwardenSession` / Fake) review closed |
| [adversarial-ledger-hello-stub.md](adversarial-ledger-hello-stub.md) | Hello AvailabilityProbe / HelloPrompt stub review closed |
| [adversarial-ledger-app-auth-pin.md](adversarial-ledger-app-auth-pin.md) | App-auth PIN/password Fake verifier (`AppAuthenticationService` / Fake protector) review closed |
| [adversarial-ledger-idle-lock.md](adversarial-ledger-idle-lock.md) | App idle-lock timeout glue (`AppIdleLockGlue` / `FakeIdleClock`) review closed |
| [adversarial-ledger-hello-unlock-ui.md](adversarial-ledger-hello-unlock-ui.md) | Hello unlock prompt UI glue (`HelloUnlockGlue` / `FakeHelloUnlockUi`) review closed |
| [adversarial-ledger-domain.md](adversarial-ledger-domain.md) | Domain review closed (73 tests) |
| [adversarial-ledger-node-change-notifier.md](adversarial-ledger-node-change-notifier.md) | Connection node change Fake pub/sub (`ConnectionNodeChangeEvent` / Fake) review closed |
| [adversarial-ledger-secrets.md](adversarial-ledger-secrets.md) | Secrets review closed (25 tests) |
| [adversarial-ledger-dpapi-paths.md](adversarial-ledger-dpapi-paths.md) | DPAPI keys/tunnels path confinement review closed |
| [adversarial-ledger-key-dpapi-crud.md](adversarial-ledger-key-dpapi-crud.md) | Private-key / tunnel DPAPI CRUD stubs (`KeyMaterialStore` / `TunnelPayloadStore`) review closed |
| [adversarial-ledger-tunnel-payload-dpapi.md](adversarial-ledger-tunnel-payload-dpapi.md) | Tunnel payload DPAPI store (`TunnelPayloadStore` / sibling `keys\` isolation) review closed |
| [adversarial-ledger-credmgr-size.md](adversarial-ledger-credmgr-size.md) | CredMgr 2560 UTF-16-byte password size guard review closed |
| [adversarial-ledger-credmgr-crud.md](adversarial-ledger-credmgr-crud.md) | CredMgr password CRUD glue (`PasswordStore` / Fake / WinCred) review closed |
| [adversarial-ledger-transient-credentials.md](adversarial-ledger-transient-credentials.md) | Transient session credential store (`Memory`/`Fake`; never SQLite) review closed |
| [adversarial-ledger-scaffold.md](adversarial-ledger-scaffold.md) | Scaffold / surface-win review closed |
| [adversarial-ledger-storage.md](adversarial-ledger-storage.md) | Storage review closed |
| [adversarial-ledger-storage-writes.md](adversarial-ledger-storage-writes.md) | Storage write path + SettingsStore review closed |
| [adversarial-ledger-folder-crud.md](adversarial-ledger-folder-crud.md) | Folder/connection tree CRUD (`create_folder` / reparent) review closed |
| [adversarial-ledger-tunnel-config-crud.md](adversarial-ledger-tunnel-config-crud.md) | TunnelConfigRepository metadata CRUD review closed |
| [adversarial-ledger-credential-metadata-crud.md](adversarial-ledger-credential-metadata-crud.md) | CredentialProfiles metadata CRUD + glue (`credential.rs` / `credential_glue`) review closed |
| [adversarial-ledger-rust-installer.md](adversarial-ledger-rust-installer.md) | Rust publish/Inno spike review closed |
| [adversarial-ledger-diagnostics.md](adversarial-ledger-diagnostics.md) | Diagnostics / soak stubs review closed |
| [adversarial-ledger-diagnostics-runner.md](adversarial-ledger-diagnostics-runner.md) | SoakRunner / FakeClock glue review closed |
| [adversarial-ledger-tunnels-mcp.md](adversarial-ledger-tunnels-mcp.md) | Tunnels / MCP / app review closed |
| [adversarial-ledger-tunnel-lease.md](adversarial-ledger-tunnel-lease.md) | TunnelManager lease glue (coalesce / UpdatedAt / cancel / secret Debug) review closed |
| [adversarial-ledger-mcp-http.md](adversarial-ledger-mcp-http.md) | MCP Streamable HTTP loopback review closed |
| [adversarial-ledger-mcp-bind.md](adversarial-ledger-mcp-bind.md) | MCP loopback bind hardening (`0.0.0.0` / mapped / zone) review closed |
| [adversarial-ledger-mcp-tools-list.md](adversarial-ledger-mcp-tools-list.md) | MCP tools/list → capability-report glue (`FakeMcpCapabilityServer`) review closed |
| [adversarial-ledger-mcp-session-registry.md](adversarial-ledger-mcp-session-registry.md) | MCP live SSH session registry Fake (`FakeMcpSessionRegistry`) review closed |
| [adversarial-ledger-mcp-approval-gate.md](adversarial-ledger-mcp-approval-gate.md) | MCP tool approval gate Fake glue (`FakeMcpToolApprovalGlue` / Approve/Deny/Cancel) review closed |
| [adversarial-ledger-protocols.md](adversarial-ledger-protocols.md) | Terminal / serial / SSH review closed |
| [adversarial-ledger-ssh-known-hosts.md](adversarial-ledger-ssh-known-hosts.md) | SSH KnownHostsStore review closed |
| [adversarial-ledger-known-hosts-prompt.md](adversarial-ledger-known-hosts-prompt.md) | SSH known_hosts prompt glue (`resolve_host_key_prompted` / session gate) review closed |
| [adversarial-ledger-ssh-host-key-verify.md](adversarial-ledger-ssh-host-key-verify.md) | SSH known_hosts verify-on-connect (`verify_host_key_on_connect` / session wrappers) review closed |
| [adversarial-ledger-ssh-auth.md](adversarial-ledger-ssh-auth.md) | SSH SshAuthMethod / authenticator stubs review closed |
| [adversarial-ledger-ssh-agent.md](adversarial-ledger-ssh-agent.md) | SSH agent availability probe (`FakeAgent` / pipe bounds) review closed |
| [adversarial-ledger-ssh-agent-auth.md](adversarial-ledger-ssh-agent-auth.md) | SSH agent ↔ auth select glue (`select_auth_methods_for_connect` / FakeFallible) review closed |
| [adversarial-ledger-ssh-reconnect.md](adversarial-ledger-ssh-reconnect.md) | SSH reconnect / backoff policy stub (`SshReconnectPolicy` / Fake schedule) review closed |
| [adversarial-ledger-session-ssh-reconnect.md](adversarial-ledger-session-ssh-reconnect.md) | Session orch Fake SSH reconnect glue (`FakeSshReconnectGlue`) review closed |
| [adversarial-ledger-ssh-socks-route.md](adversarial-ledger-ssh-socks-route.md) | SSH SOCKS5 tunnel route select (`select_ssh_connect_target` / FakeTunnelSocks) review closed |
| [adversarial-ledger-ssh-kbi.md](adversarial-ledger-ssh-kbi.md) | SSH keyboard-interactive multi-prompt Fake channel (`FakeKbiChannel` / `answer_kbi_round`) review closed |
| [adversarial-ledger-serial-enumerate.md](adversarial-ledger-serial-enumerate.md) | Serial port enumeration review closed |
| [adversarial-ledger-serial-picker.md](adversarial-ledger-serial-picker.md) | Serial COM host-field picker glue (`wormhole-ui`) review closed |
| [adversarial-ledger-serial-presets.md](adversarial-ledger-serial-presets.md) | Serial baud/parity preset VM glue (`SerialLineCombo` / DCB / editor↔QC) review closed |
| [adversarial-ledger-webview.md](adversarial-ledger-webview.md) | WebView2 / gates 3–5 review closed |
| [adversarial-ledger-webview-cert.md](adversarial-ledger-webview-cert.md) | WebView2 `cert_policy_to_webview2_behavior` adapter review closed |
| [adversarial-ledger-rdp.md](adversarial-ledger-rdp.md) | RDP overlay spike review closed |
| [adversarial-ledger-rdp-credssp.md](adversarial-ledger-rdp-credssp.md) | RDP CredSSP / configure review closed |
| [adversarial-ledger-rdp-credssp-wipe.md](adversarial-ledger-rdp-credssp-wipe.md) | RDP CredSSP wipe ↔ connect Fake glue review closed |
| [adversarial-ledger-rdp-gateway.md](adversarial-ledger-rdp-gateway.md) | RDP gateway / tunnel policy review closed (2026-07-31 re-audit: solid; parent SKIP) |
| [adversarial-ledger-rdp-external.md](adversarial-ledger-rdp-external.md) | RDP external mstsc + tunnel policy review closed (2026-07-31 re-audit: solid; parent SKIP) |
| [adversarial-ledger-rdp-external-mstsc.md](adversarial-ledger-rdp-external-mstsc.md) | RDP external mstsc Fake policy glue (`RdpExternalMstscGlue`) review closed |
| [adversarial-ledger-rdp-strict-auth.md](adversarial-ledger-rdp-strict-auth.md) | RDP tunnel + strict server-auth policy review closed (2026-07-31 re-audit: solid; parent SKIP) |
| [adversarial-ledger-rdp-resolution.md](adversarial-ledger-rdp-resolution.md) | RDP ResolutionDebouncer review closed |
| [adversarial-ledger-rdp-resize-glue.md](adversarial-ledger-rdp-resize-glue.md) | RDP `RdpResolutionLayoutGlue` / Fake resize glue review closed |
| [adversarial-ledger-rdp-display-redirect.md](adversarial-ledger-rdp-display-redirect.md) | RDP display/redirect Fake configure glue (`RdpDisplayRedirectGlue`) review closed |
| [adversarial-ledger-rdp-performance-flags.md](adversarial-ledger-rdp-performance-flags.md) | RDP performance flags / bitmap-cache Fake configure glue (`RdpPerformanceFlagsGlue`) review closed |
| [adversarial-ledger-rdp-forwarder.md](adversarial-ledger-rdp-forwarder.md) | RDP `select_rdp_connect_target` / LocalForwarder stub review closed |
| [adversarial-ledger-focus-a11y.md](adversarial-ledger-focus-a11y.md) | FocusBroker + a11y (gates 7–8) review closed |
| [adversarial-ledger-focus-cycle.md](adversarial-ledger-focus-cycle.md) | FocusCycle ring + FocusBroker integration review closed |
| [adversarial-ledger-wireguard-establish.md](adversarial-ledger-wireguard-establish.md) | WireGuard establish-path glue (establish_wireguard / Fake / PayloadStoreSecretLookup) review closed |
| [adversarial-ledger-tunnels-sidecar.md](adversarial-ledger-tunnels-sidecar.md) | WireGuard sidecar review closed |
| [adversarial-ledger-ui-vnc-http.md](adversarial-ledger-ui-vnc-http.md) | UI / VNC / HTTP review closed |
| [adversarial-ledger-http-cert.md](adversarial-ledger-http-cert.md) | `HttpCertPolicy` / resolve_cert_policy review closed |
| [adversarial-ledger-http-cert-glue.md](adversarial-ledger-http-cert-glue.md) | HTTP ignore-cert → WebView2 AlwaysAllow leaf/target glue review closed |
| [adversarial-ledger-http-route.md](adversarial-ledger-http-route.md) | HTTP SOCKS vs local-forwarder selection — full gates (2 adv + 3 simplify) |
| [adversarial-ledger-http-nav-report.md](adversarial-ledger-http-nav-report.md) | HTTP/HTTPS nav-result → session-status Fake glue review closed |
| [adversarial-ledger-http-profile-wipe.md](adversarial-ledger-http-profile-wipe.md) | HTTP/HTTPS WebView2 profile isolation / wipe Fake glue review closed |
| [adversarial-ledger-http-new-window.md](adversarial-ledger-http-new-window.md) | HTTP/HTTPS new-window / popup policy Fake glue review closed |
| [adversarial-ledger-vnc-framebuffer.md](adversarial-ledger-vnc-framebuffer.md) | VNC framebuffer / input queue review closed |
| [adversarial-ledger-vnc-forwarder.md](adversarial-ledger-vnc-forwarder.md) | VNC `select_vnc_connect_target` / LocalForwarder stub review closed |
| [adversarial-ledger-vnc-session-glue.md](adversarial-ledger-vnc-session-glue.md) | VNC session glue (`push_*` / `apply_framebuffer_rect` / Fake dirty notify) review closed |
| [adversarial-ledger-vnc-input-resize.md](adversarial-ledger-vnc-input-resize.md) | VNC input queue drain/coalesce on resize + disconnect Fake glue review closed |
| [adversarial-ledger-vnc-clipboard.md](adversarial-ledger-vnc-clipboard.md) | VNC clipboard cut-text glue (`clipboard_glue` ClientCutText / ServerCutText) review closed |
| [adversarial-ledger-vnc-password-auth.md](adversarial-ledger-vnc-password-auth.md) | VNC password-only auth glue (`auth_glue` / `FakeVncPasswordProvider`) review closed |
| [adversarial-ledger-gpui-gates.md](adversarial-ledger-gpui-gates.md) | GPUI gates 1–2 review closed |
| [adversarial-ledger-sftp-vpn.md](adversarial-ledger-sftp-vpn.md) | SFTP + OpenVPN/Fortinet review closed |
| [adversarial-ledger-sftp-cancel.md](adversarial-ledger-sftp-cancel.md) | SFTP single-flight cancel / gate review closed |
| [adversarial-ledger-sftp-socks.md](adversarial-ledger-sftp-socks.md) | SFTP `select_sftp_transport` SOCKS routing review closed |
| [adversarial-ledger-sftp-dialog.md](adversarial-ledger-sftp-dialog.md) | SFTP file-transfer dialog glue (`ConnectedSshContext` / `start_transfer`) review closed |
| [adversarial-ledger-sftp-progress.md](adversarial-ledger-sftp-progress.md) | SFTP transfer progress callback glue (`report_progress` / Fake chunks) review closed |
| [adversarial-ledger-sftp-prewarm.md](adversarial-ledger-sftp-prewarm.md) | SFTP client prewarm / borrow Fake glue (`SftpPrewarmGlue` / `BorrowedShellTunnel`) review closed |
| [adversarial-ledger-sftp-conflict.md](adversarial-ledger-sftp-conflict.md) | SFTP transfer conflict overlay policy (`resolve_conflict_overlay` / Fake) review closed |
| [adversarial-ledger-import-vpn.md](adversarial-ledger-import-vpn.md) | Import + remaining VPN review closed |
| [adversarial-ledger-import-unsupported.md](adversarial-ledger-import-unsupported.md) | Import UnsupportedProtocol / HTTP-HTTPS-Serial soft-skip review closed |
| [adversarial-ledger-import-apply.md](adversarial-ledger-import-apply.md) | Import plan → SQLite apply stub (`insert_many` / soft-skip / password OOB) review closed |
| [adversarial-ledger-import-skip-report.md](adversarial-ledger-import-skip-report.md) | Import soft-skip UI report glue (`ImportSkipReport` / Fake) review closed |
| [adversarial-ledger-crypto-auth.md](adversarial-ledger-crypto-auth.md) | AES-GCM + ovpn auth glue review closed |
| [adversarial-ledger-otp-prompt.md](adversarial-ledger-otp-prompt.md) | OTP / SecondFactorPrompt stub review closed |
| [adversarial-ledger-otp-ui.md](adversarial-ledger-otp-ui.md) | OTP prompt UI glue (`OtpPromptChannel` / Fake) review closed |
| [adversarial-ledger-watchguard-auth.md](adversarial-ledger-watchguard-auth.md) | WatchGuard Firebox auth stub review closed |
| [adversarial-ledger-watchguard-establish.md](adversarial-ledger-watchguard-establish.md) | WatchGuard establish-path glue (`establish_watchguard` / `_crv1` / `_portal`) review closed |
| [adversarial-ledger-fortinet-saml.md](adversarial-ledger-fortinet-saml.md) | Fortinet SamlAuthFlow stub review closed |
| [adversarial-ledger-fortinet-saml-ui.md](adversarial-ledger-fortinet-saml-ui.md) | Fortinet SAML prompt UI glue (`SamlPromptChannel` / Fake) review closed |
| [adversarial-ledger-fortinet-establish.md](adversarial-ledger-fortinet-establish.md) | Fortinet establish-path glue (`establish_fortinet` / settings → sidecar) review closed |
| [adversarial-ledger-entra-token.md](adversarial-ledger-entra-token.md) | Azure VPN EntraTokenProvider stub review closed |
| [adversarial-ledger-entra-token-cache.md](adversarial-ledger-entra-token-cache.md) | Azure Entra refresh-token DPAPI cache glue review closed |
| [adversarial-ledger-azure-establish.md](adversarial-ledger-azure-establish.md) | Azure VPN establish-path glue (`establish_azure` / `establish_azure_from_entra`) review closed |
| [adversarial-ledger-rdp-ole.md](adversarial-ledger-rdp-ole.md) | RDP OLE in-place review closed |
| [adversarial-ledger-forwarder.md](adversarial-ledger-forwarder.md) | SOCKS5 + local forwarder review closed |
| [adversarial-ledger-ui-chrome.md](adversarial-ledger-ui-chrome.md) | UI GPUI chrome review closed |
| [adversarial-ledger-update-logging.md](adversarial-ledger-update-logging.md) | Update + logging review closed |
| [adversarial-ledger-log-redaction.md](adversarial-ledger-log-redaction.md) | `redact_log_text` assignment scrubbing review closed |
| [adversarial-ledger-logging-boot.md](adversarial-ledger-logging-boot.md) | Logging boot/settings → redaction glue (`apply_logging_boot` / `FakeLogSink`) review closed |
| [adversarial-ledger-update-channel.md](adversarial-ledger-update-channel.md) | UpdateChecker / NetworkStub / Fake / UpdateApiToken review closed |
| [adversarial-ledger-update-notify.md](adversarial-ledger-update-notify.md) | Update check UI notify glue (`check_now` / `UpdateNotifyGlue` stamp/skip/startup) review closed |
| [adversarial-ledger-terminal-bridge.md](adversarial-ledger-terminal-bridge.md) | Terminal bridge + gate05 review closed |
| [adversarial-ledger-clipboard-auto-sudo.md](adversarial-ledger-clipboard-auto-sudo.md) | HostClipboard + auto-sudo detector review closed |
| [adversarial-ledger-auto-sudo-session-glue.md](adversarial-ledger-auto-sudo-session-glue.md) | Auto-sudo session glue (`AutoSudoSessionGlue` / FakeTerminalSession) review closed |
| [adversarial-ledger-terminal-paste.md](adversarial-ledger-terminal-paste.md) | Terminal paste chunking / ClipboardHook Debug review closed |
| [adversarial-ledger-clipboard-paste.md](adversarial-ledger-clipboard-paste.md) | Paste → session write glue (`paste_request_to_session` / Fake) review closed |
| [adversarial-ledger-terminal-settings-apply.md](adversarial-ledger-terminal-settings-apply.md) | Terminal font/size/auto-copy settings apply glue (`settings_apply` / `terminal_apply` / Fake) review closed |
| [adversarial-ledger-pane-layout.md](adversarial-ledger-pane-layout.md) | BrokerPaneLayoutSink / pane-layout review closed |
| [adversarial-ledger-pane-focus.md](adversarial-ledger-pane-focus.md) | Pane focus activate/cycle ↔ FocusCycle glue review closed |
| [adversarial-ledger-broker-session-surface.md](adversarial-ledger-broker-session-surface.md) | Session open/close ↔ Fake broker bind/unbind glue review closed |
| [adversarial-ledger-pane-split.md](adversarial-ledger-pane-split.md) | PaneLayout split/merge + Workspace/Shell wiring review closed |
| [adversarial-ledger-pane-split-notify.md](adversarial-ledger-pane-split-notify.md) | Pane split/merge → BrokerPaneLayoutSink notify glue review closed |
| [adversarial-ledger-quick-connect.md](adversarial-ledger-quick-connect.md) | Quick Connect state review closed |
| [adversarial-ledger-quick-connect-delta.md](adversarial-ledger-quick-connect-delta.md) | Quick Connect delta (tunnel / Debug / labels) review closed |
| [adversarial-ledger-qc-session-connect.md](adversarial-ledger-qc-session-connect.md) | Quick Connect → session orchestrator glue review closed |
| [adversarial-ledger-qc-history.md](adversarial-ledger-qc-history.md) | Quick Connect recent-history MRU VM glue review closed |
| [adversarial-ledger-session.md](adversarial-ledger-session.md) | Session orchestrator review closed (27 tests) |
| [adversarial-ledger-session-rdp-vnc.md](adversarial-ledger-session-rdp-vnc.md) | Session RDP/VNC stubs review closed |
| [adversarial-ledger-session-tabs.md](adversarial-ledger-session-tabs.md) | SessionTabBarState / ProtocolBadge review closed |
| [adversarial-ledger-session-tab-orch.md](adversarial-ledger-session-tab-orch.md) | Session tab ↔ orchestrator glue review closed |
| [adversarial-ledger-tab-close-dispose.md](adversarial-ledger-tab-close-dispose.md) | Tab close → orchestrator dispose (`SessionBindings` / cancel / lease) review closed |
| [adversarial-ledger-stormshield-auth.md](adversarial-ledger-stormshield-auth.md) | Stormshield SNS auth_glue stub review closed |
| [adversarial-ledger-stormshield-establish.md](adversarial-ledger-stormshield-establish.md) | Stormshield SNS establish-path glue (`establish_stormshield` / `_sns`) review closed |
| [adversarial-ledger-cisco-auth.md](adversarial-ledger-cisco-auth.md) | Cisco aggregate-auth stub review closed |
| [adversarial-ledger-cisco-establish.md](adversarial-ledger-cisco-establish.md) | Cisco establish-path glue review closed |
| [adversarial-ledger-openvpn-establish.md](adversarial-ledger-openvpn-establish.md) | OpenVPN establish-path glue (`establish_openvpn` / Fake lookups) review closed |

## Rust workspace

Parallel tree (does not replace the .NET production app):

```text
rust/
  Cargo.toml
  crates/
    surface-lab/
    wormhole-surface-win/
    wormhole-secrets-win/
    wormhole-domain/
    wormhole-storage/
    wormhole-testkit/
    wormhole-terminal/
    wormhole-serial/
    wormhole-ssh/
    wormhole-tunnels/
    wormhole-mcp/
    wormhole-app/
    wormhole-ui/
    wormhole-vnc/
    wormhole-http/
    wormhole-sftp/
    wormhole-import/
    wormhole-update/
    wormhole-diagnostics/
    wormhole-session/
```

WinUI remains production until Phase 7 cutover.

### Serial port enumeration (`wormhole-serial`)

`list_serial_ports()` / `SerialPortEnumerator` is the Rust library API for COM names (system soft-fails to `[]` on OS/permission errors; fakes stay deterministic). Port names are validated by `normalize_serial_port_name` before open — hostile CreateFile shapes are rejected. Tests inject `MemorySerialPortEnumerator` / `FakeSerialPortEnumerator` so CI never needs a real device. Session I/O remains separate (`SerialSession` + `SerialPortHandle`).

**UI host-field glue (no GPUI):** `wormhole_ui::SerialPortPickerState` refreshes via the enumerator and selects a COM line into connection-editor / Quick Connect `Host` when protocol is Serial. Enumerator `Err` and empty lists fail closed (clear list; selection refuses OOB / non-Serial). System OS soft-fail is `Ok([])` (not `refresh_failed`). This is **not** a shipped product COM combo chrome — GPUI binding is still separate. See [adversarial-ledger-serial-picker.md](adversarial-ledger-serial-picker.md).

## Parallel workstreams (kickoff)

1. Phase 0 baseline inventory  
2. Cargo `surface-lab` scaffold  
3. Dependency pin research  
4. Native surface broker analysis from current RDP/WebView2 hosts  
