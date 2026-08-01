# Migration backlog (still to do)

**Source of truth for row-level status:** [feature-matrix.md](feature-matrix.md).  
**Closed Lab Fake glues / ledgers:** [README.md](README.md).  
**Hardware gates (not Lab):** [gate-checklist.md](gate-checklist.md) · [gate-evidence-log.md](gate-evidence-log.md).

WinUI 3/C# remains production. Do **not** claim `HardwarePass` or cutover. This file lists **open** work only (Spike → Lab, Lab → GPUI/live, gates, cutover). Refresh from the matrix when closing a wave.

---

## Hard stops (before product cutover)

- [ ] Surface-lab gates **1–8** on real **x64** and **ARM64** → `HardwarePass` in the evidence log ([gate-checklist.md](gate-checklist.md))
- [ ] Gates **3–8** are kill switches (WebView2 panes, z-order, xterm, RDP owned overlay, focus, a11y)
- [ ] Phase 7 cutover checklist ([15-cutover.md](15-cutover.md)) — parallel Inno, DB/CredMgr/DPAPI compatibility, rollback — **only after** hardware gates

---

## GPUI / product chrome (Lab glue exists; UI not shipped)

Almost every Lab row still needs GPUI (or live surface) wiring. Highest-impact:

| Area | Remaining |
|---|---|
| Shell | Product GPUI shell (nav, Mica title bar, sidebar) beyond skeleton (`gpui` feature) |
| Tree | Tree chrome, search UI, drag-reorder UX, dialogs (folder / connection / duplicate) |
| Settings | General / Security / Extensions / Updates / MCP pages (Security + MCP section VM glue closed — [adversarial-ledger-settings-mcp-security.md](adversarial-ledger-settings-mcp-security.md)) |
| Sessions | Tab close-confirm UX (Lab VM glue closed — [adversarial-ledger-tab-close-confirm.md](adversarial-ledger-tab-close-confirm.md)); connection-progress overlay; Quick Connect bar/dialog |
| Creds / tunnels | Credentials page + credential picker UI; tunnel configs / editor / test dialogs |
| Layout | Multi-pane drag chrome / drop overlay |
| Dialogs | Content-dialog gate vs RDP overlay suppress |
| Import / backup | mRemoteNG + backup GPUI dialogs / path pickers |

---

## Live engines & surfaces (Spike / fail-closed → real I/O)

### Protocols

- [ ] **SSH** — live russh dial + WebView2/xterm rebind; reconnect UI; KBI/agent beyond Fake; host-key prompt dialog; auto-sudo live shell; SOCKS CONNECT dial
- [ ] **SFTP** — live `russh-sftp` + dual-pane GPUI; drag/strip binding; legacy browser page deprioritized
- [ ] **Serial** — GPUI terminal + COM combo (orch Lab exists)
- [x] **HTTP/HTTPS** — live WebView2 session host; profile wipe on disk (**Lab — [adversarial-ledger-http-profile-fs.md](adversarial-ledger-http-profile-fs.md)**); still open: live session host, `NewWindowRequested`, Bitwarden extension host
- [ ] **VNC** — live TCP/`engine`; orch still `UnsupportedProtocol`; GPUI framebuffer surface
- [ ] **RDP** — live OCX connect/reconnect; owned-overlay broker on product shell; audio + live property apply; live `mstsc`/WAM launch; DriveCollection enum (**Lab parity module closed — [adversarial-ledger-rdp-drive-list.md](adversarial-ledger-rdp-drive-list.md)**; live OCX enum open); full dialog gate

### Tunnels / VPN

- [ ] WireGuard / OpenVPN — product UX beyond sidecar spawn Lab
- [ ] Fortinet — full SAML WebView2 / external-browser UI (not Fake channel only)
- [x] WatchGuard — Firebox auth into establish (**Lab — [adversarial-ledger-tunnels-os-adapters-watchguard.md](adversarial-ledger-tunnels-os-adapters-watchguard.md)**); still open: live portal HTTP
- [x] Stormshield — portal/cache/ConfirmTrust + physical-path **Fake glue** (Lab — [adversarial-ledger-stormshield-portal.md](adversarial-ledger-stormshield-portal.md)); still open: live portal HTTP + SSO
- [ ] Azure VPN — interactive Entra WebView2 + silent refresh
- [ ] Cisco Secure Client — STF/CSTP (beyond aggregate-auth typing stub)
- [ ] End-to-end routing matrix on product shell (SSH/SFTP SOCKS, RDP/VNC forwarder, HTTP hybrid)
- [x] Live `dnsapi` / `iphlpapi` physical-path (**Lab — `Win32AdapterSource` / `Win32PhysicalNetworkPathProbe`, [adversarial-ledger-tunnels-os-adapters-watchguard.md](adversarial-ledger-tunnels-os-adapters-watchguard.md)**); socket connect host-side
- [ ] OTP / TLS / route prompts — real dialogs (Fake channels exist)

### Secrets / Bitwarden / app lock

- [x] Bitwarden — **SQLite cache repo** (Lab — [adversarial-ledger-bitwarden-cache-repo.md](adversarial-ledger-bitwarden-cache-repo.md)); still open: live `bw` spawn, HTTP download + ZIP extract, unlock prompt UI, picker wiring
- [ ] Bitwarden browser — extension host in HTTPS profiles (Spike helpers only)
- [x] App lock — `GetLastInputInfo` sampler (Lab — [adversarial-ledger-os-idle.md](adversarial-ledger-os-idle.md)) + Settings Security section VM (Lab — [adversarial-ledger-settings-mcp-security.md](adversarial-ledger-settings-mcp-security.md)) + **Hello consent glue** (Lab — [adversarial-ledger-hello-consent-ssh-resolver.md](adversarial-ledger-hello-consent-ssh-resolver.md)); still open: **WinRT consent I/O**, GPUI Security chrome
- [x] Credential binding service UI (**Lab — [adversarial-ledger-credential-binding.md](adversarial-ledger-credential-binding.md)**); SSH full password resolver + unlock prompt (**Lab — [adversarial-ledger-hello-consent-ssh-resolver.md](adversarial-ledger-hello-consent-ssh-resolver.md)**); still open: product prompt/GPUI
- [ ] Transient cred / QC — shell/session DI wiring

### MCP / update / diagnostics

- [x] MCP — Settings toggle VM glue (Lab — [adversarial-ledger-settings-mcp-security.md](adversarial-ledger-settings-mcp-security.md)) + **tool runner + live tab scan glue** (Lab — [adversarial-ledger-mcp-tool-runner-scan.md](adversarial-ledger-mcp-tool-runner-scan.md)); still open: live SSH runner / HTTP dispatch, GPUI exit-order wiring
- [x] Update — **installer launch + changelog VM glue** (Lab — [adversarial-ledger-update-installer.md](adversarial-ledger-update-installer.md)); still open: live GitHub HTTP, GPUI installer/changelog UX
- [x] Crash — WER/dumps (**Lab — `CrashDiagnosticsGlue` / `FakeWerRegistry`, [adversarial-ledger-crash-wer.md](adversarial-ledger-crash-wer.md)**); live WER registration Pending

### Cross-cutting Lab gaps called out in the matrix

- [x] Node-change notifier → tree Lab subscriber glue (Lab — [adversarial-ledger-tree-node-change.md](adversarial-ledger-tree-node-change.md)); still open: session/GPUI host wiring
- [ ] Terminal font/size/auto-copy → live xterm options
- [x] MCP session registry → live open-tab scan (**Lab — [adversarial-ledger-mcp-tool-runner-scan.md](adversarial-ledger-mcp-tool-runner-scan.md)**)

---

## Explicitly deferred / low priority

- [ ] Legacy SFTP browser page (`SftpBrowserPage`) — intentionally deprioritized (dialog path is primary)

---

## How to use

1. Pick open items that are still **Spike / Pending** or say **GPUI / live Pending** in [feature-matrix.md](feature-matrix.md).
2. Implement Lab Fake glue first when possible; run adversarial-review-fix per [adversarial-review-policy.md](adversarial-review-policy.md).
3. Update the matrix row + add/close an adversarial ledger; tick or remove the matching bullet here.
4. Never mark Rust as Production here or in the matrix.
