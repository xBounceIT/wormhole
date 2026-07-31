# 16 — Session orchestrator (`wormhole-session`)

**Status:** skeleton crate — Serial / SSH (password) / HTTP target dispatch + optional tunnel lease; RDP/VNC typed stubs; UI callers prepare via tree Open / Quick Connect glue  

**Date:** 2026-07-31  

## Scope

Starts a protocol session from a **resolved** [`ConnectionProfile`](../../rust/crates/wormhole-domain/src/connection_profile.rs) (or a sufficiently populated [`ConnectionNode`](../../rust/crates/wormhole-domain/src/connection_node.rs) via `profile_from_node` / `connect_node`).

| Step | Behavior |
|---|---|
| State | `Connecting` → `Connected` **or** `Failed`; `close()` → `Closed` |
| Cancel | `tokio_util::sync::CancellationToken` on `ConnectOptions` (checked before/during tunnel + protocol); cancel lands `Failed` + `Cancelled`, never leaves `Connecting`. Tab close glue cancels the same token via [`close_tab_and_dispose_session`](../../rust/crates/wormhole-app/src/session_tabs.rs). |
| Tunnel | When `tunnel_enabled` **and** protocol ≠ Serial **and** protocol is supported: establish a [`TunnelLease`](../../rust/crates/wormhole-tunnels/src/lease.rs) before connect; release on fail/cancel |
| Serial | `wormhole-serial` (fake COM in unit tests) — **never** opens a tunnel |
| SSH | `wormhole-ssh` password path; route select `select_ssh_connect_target` / `FakeTunnelSocks` (`TunnelEnabled` → Direct/Socks5; fail-closed missing SOCKS; Serial never); SOCKS5 dial when the lease exposes a SOCKS endpoint (CONNECT still stub); host-key **verify** stub `verify_ssh_host_key` (Accept / Reject / Prompt; Fake store; LabOnly) + gate stub `gate_ssh_host_key` / `FakeKnownHosts` (prompt Accept-pin / Reject fail-closed; no live SSH in unit tests; orchestrator still uses `ssh_accept_any_host_key` until UI prompt is wired); reconnect/backoff policy lives in `wormhole_ssh::reconnect` (`SshReconnectPolicy` / `FakeBackoffSchedule`; orch loop Pending) |
| HTTP/HTTPS | Builds `wormhole-http` `HttpConnectionTarget` (direct / SOCKS / local forwarder when no SOCKS) — WebView2 hosting stays in surface-win |
| RDP / VNC | Prepare [`RdpConnectRequest`](../../rust/crates/wormhole-session/src/rdp_vnc.rs) / [`VncConnectRequest`](../../rust/crates/wormhole-session/src/rdp_vnc.rs) (host, port, tunnel flags; no COM/OLE/VNC engine), then fail closed with `SessionError::UnsupportedProtocol { protocol, reason }` **before** any tunnel establish. `SessionKind::Rdp` / `Vnc` mark surface stubs for UI branching. VNC framebuffer/input glue lives in `wormhole-vnc::session_glue` (Fake dirty notify; no orch connect). |

## UI callers (pure state glue in `wormhole-ui`)

The orchestrator itself does **not** load the connection tree. Callers resolve a profile first, then pass it (plus [`ConnectOptions`](../../rust/crates/wormhole-session/src/orchestrator.rs)) into `SessionOrchestrator::connect`.

| Path | Module | Prepare | Connect |
|---|---|---|---|
| Tree double-click / Open / selection | [`tree/open.rs`](../../rust/crates/wormhole-ui/src/tree/open.rs) (`wormhole-ui` feature `session`, default) — see [17-tree-settings-vm.md](17-tree-settings-vm.md) | `prepare_connect_request` / `prepare_tree_connect` / `prepare_tree_connect_from_selection` → persisted `ConnectRequest` / `TreeConnectRequest` via `InheritanceResolver` over a full snapshot; **folders fail closed**; password via `options_with_password` or host `CredentialResolver` | `connect` / `connect_prepared` / `connect_from_tree` / `connect_from_selection` (+ crate-root `connect_tree` / `connect_tree_prepared`) |
| Quick Connect accept | [`quick_connect/session_connect.rs`](../../rust/crates/wormhole-ui/src/quick_connect/session_connect.rs) (same `session` feature) — see [21-quick-connect.md](21-quick-connect.md) | `prepare_connect` / `prepare_connect_ephemeral` → ephemeral profile + out-of-band password on `ConnectOptions`; tunnel flags on profile, tunnel args caller-owned | `connect_prepared` / `connect_quick_connect` (no DPAPI tunnel load) |

Unit tests for both paths inject `FakeSerialConnector` / `FakeSshConnector` (and optional `FakeTunnelBroker` / `FakeCredentialResolver`) via `SessionOrchestrator::for_tests` / `new`. Tree tests use `MemoryConnectionSource` and cover RDP/VNC `UnsupportedProtocol` fail-closed.

## Injected backends

Production and tests share the same orchestrator; swap connectors:

| Trait | Live | Fake |
|---|---|---|
| `SerialConnector` | `LiveSerialConnector` | `FakeSerialConnector` |
| `SshConnector` | `LiveSshConnector` | `FakeSshConnector` |
| `TunnelBroker` | `ManagerTunnelBroker` | `FakeTunnelBroker` |
| `CredentialResolver` | (host CredMgr/DPAPI) | `FakeCredentialResolver` |
| RDP / VNC | `StubRdpConnector` / `StubVncConnector` (prepare + `UnsupportedProtocol`) | same |

Passwords and tunnel secret blobs are **never** interpolated into `SessionError` / `Display` / `Debug` of `ConnectOptions` (password field shows `<redacted>`).

## Non-goals (this crate)

- WinUI / GPUI session tabs or chrome
- RDP ActiveX / VNC framebuffer hosts
- Creating WebView2 environments
- Key-based SSH (password path only for now)
- Loading `ConnectionNodeSource` / tree UI (owned by `wormhole-ui`)

## Session tab glue (`wormhole-app`)

[`SessionHandle::id`](../../rust/crates/wormhole-session/src/orchestrator.rs) is allocated at connect start (fresh UUID, or `ConnectOptions.session_id` when the caller pre-registers a tab). Composition-root helpers in [`wormhole-app::session_tabs`](../../rust/crates/wormhole-app/src/session_tabs.rs):

| Helper | Role |
|---|---|
| `open_tab_for_session` / `close_tab_on_session_closed` | Map orch [`SessionId`](../../rust/crates/wormhole-session/src/id.rs) ↔ [`SessionTabBarState`](../../rust/crates/wormhole-ui/src/session_tab_bar.rs) (UUID bits via `to_ui_session_id` / `from_ui_session_id`). Open fail-closes on duplicate; close-on-session-closed is idempotent. |
| `SessionBindings` + `close_tab_and_dispose` / `close_tab_and_dispose_session` | User tab close → cancel in-flight connect + [`SessionHandle::close`](../../rust/crates/wormhole-session/src/orchestrator.rs) (protocol dispose + tunnel lease drop). Unknown binding no-op; handle id mismatch fail-closed. `attach_handle`: orphan (binding gone) → dispose + `Ok`; already-connected → fail-closed `DuplicateBinding`. |

Pure state + Fake connectors only — no GPUI window. See [08-ui.md](08-ui.md).

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-session
cargo test -p wormhole-ui
cargo test -p wormhole-app --test services_smoke
cargo test -p wormhole-app --lib session_tabs
```

Adversarial ledgers: [`adversarial-ledger-session.md`](adversarial-ledger-session.md) (orchestrator), [`adversarial-ledger-session-rdp-vnc.md`](adversarial-ledger-session-rdp-vnc.md) (RDP/VNC stubs), [`adversarial-ledger-session-tabs.md`](adversarial-ledger-session-tabs.md) (`SessionTabBarState`), [`adversarial-ledger-session-tab-orch.md`](adversarial-ledger-session-tab-orch.md) (app tab ↔ orchestrator glue), [`adversarial-ledger-tab-close-dispose.md`](adversarial-ledger-tab-close-dispose.md) (tab close → dispose), [`adversarial-ledger-qc-session-connect.md`](adversarial-ledger-qc-session-connect.md) (Quick Connect → orchestrator glue).
