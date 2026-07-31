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
| Settings | General / Security / Extensions / Updates / MCP pages |
| Sessions | Tab close-confirm UX; connection-progress overlay; Quick Connect bar/dialog |
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
- [ ] **HTTP/HTTPS** — live WebView2 session host; profile wipe on disk; `NewWindowRequested`; Bitwarden extension host
- [ ] **VNC** — live TCP/`engine`; orch still `UnsupportedProtocol`; GPUI framebuffer surface
- [ ] **RDP** — live OCX connect/reconnect; owned-overlay broker on product shell; audio + live property apply; live `mstsc`/WAM launch; DriveCollection enum; full dialog gate

### Tunnels / VPN

- [ ] WireGuard / OpenVPN — product UX beyond sidecar spawn Lab
- [ ] Fortinet — full SAML WebView2 / external-browser UI (not Fake channel only)
- [ ] WatchGuard — wire Firebox auth into establish
- [ ] Stormshield — portal/cache/SSO + ConfirmTrust + physical-path wiring
- [ ] Azure VPN — interactive Entra WebView2 + silent refresh
- [ ] Cisco Secure Client — STF/CSTP (beyond aggregate-auth typing stub)
- [ ] End-to-end routing matrix on product shell (SSH/SFTP SOCKS, RDP/VNC forwarder, HTTP hybrid)
- [ ] Live `dnsapi` / `iphlpapi` physical-path (Fake only today)
- [ ] OTP / TLS / route prompts — real dialogs (Fake channels exist)

### Secrets / Bitwarden / app lock

- [ ] Bitwarden — live `bw` spawn, HTTP download + ZIP extract, SQLite cache repo, unlock prompt UI, picker wiring
- [ ] Bitwarden browser — extension host in HTTPS profiles (Spike helpers only)
- [ ] App lock — WinRT Hello consent + `GetLastInputInfo`; Settings Security UI
- [ ] Credential binding service UI; SSH full password resolver + unlock prompt
- [ ] Transient cred / QC — shell/session DI wiring

### MCP / update / diagnostics

- [ ] MCP — Settings toggle; live SSH tool runner / HTTP dispatch; GPUI exit-order wiring
- [ ] Update — live GitHub HTTP + installer / changelog UX
- [ ] Crash — WER/dumps beyond diagnostics placeholders

### Cross-cutting Lab gaps called out in the matrix

- [ ] Node-change notifier → tree/session GPUI subscribers
- [ ] Terminal font/size/auto-copy → live xterm options
- [ ] MCP session registry → live open-tab scan

---

## Explicitly deferred / low priority

- [ ] Legacy SFTP browser page (`SftpBrowserPage`) — intentionally deprioritized (dialog path is primary)

---

## How to use

1. Pick open items that are still **Spike / Pending** or say **GPUI / live Pending** in [feature-matrix.md](feature-matrix.md).
2. Implement Lab Fake glue first when possible; run adversarial-review-fix per [adversarial-review-policy.md](adversarial-review-policy.md).
3. Update the matrix row + add/close an adversarial ledger; tick or remove the matching bullet here.
4. Never mark Rust as Production here or in the matrix.
