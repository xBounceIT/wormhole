# Quick Connect state — `wormhole-ui`

**Status:** pure Rust state / validation (no GPUI)  
**Date:** 2026-07-31  
**Crate module:** `wormhole_ui::quick_connect`  
**C# source of truth:** `Views/Controls/QuickConnectBar`, `ViewModels/QuickConnectViewModel.cs`, `Services/DialogService.PromptQuickConnectCoreAsync`, `Models/QuickConnectResult.cs`

> Independent of GPUI chrome and of the full connection-editor dialog surface.
> The bar in C# is a single button that opens the ephemeral editor; this module owns
> the **seed → edit → validate → ephemeral node/profile** state machine that feeds
> tab open + transient credentials.

**Context7 MCP:** unavailable in this environment; pins follow workspace `Cargo.toml` / `deps-pins.md`.

## Scope

| Type / fn | Role |
|---|---|
| `QuickConnectState` | Protocol picker, host/port or serial line, optional tunnel, validate / build |
| `QuickConnectResult` | Ephemeral `ConnectionNode` + out-of-band session password (never on the node; Debug/Display redact) |
| `TargetField` | Host / Address / Serial line labels for the primary target input |
| `protocol_picker` / `PROTOCOL_PICKER` | SSH, RDP, HTTP, HTTPS, Serial, VNC (no retired SFTP) |
| `default_port` | Inheritance default-port table (22 / 3389 / 80 / 443 / 5900 / 0) |
| `seed_connection_node` | DialogService seed: SSH, `CredentialMode=None`, `SerialDefaults`, `TunnelEnabled=false` |
| `try_build` | Validate → write node (`include_pending_inline_password: false`) → take password → blank name → host |
| `try_build_ephemeral_profile` | Solo-node `InheritanceResolver` + `is_ephemeral = true` |
| `prepare_connect` / `prepare_connect_ephemeral` | QC accept → ephemeral profile + `ConnectOptions` (password out-of-band only) |
| `connect_prepared` / `connect_quick_connect` | Call `SessionOrchestrator::connect` (unit tests use Fake serial/SSH) |
| `QuickConnectConnectRequest` | Prepared profile + options; `Debug` redacts password via `ConnectOptions` |
| `QuickConnectHistoryVm` | Recent successful QC targets (`protocol+host[+port]`); capped MRU; Fake store |
| Chrome helpers | `name_header` / `name_placeholder` / `credential_placeholder` / `tunnel_help_text` / `ssh_auto_sudo_choices` |

Internally wraps `ConnectionEditorState` in `ConnectionEditorMode::QuickConnect` so advanced RDP / tunnel / credential fields stay available via `editor()` / `editor_mut()` without duplicating the validation matrix. See [20-connection-editor.md](20-connection-editor.md).

## Validation (Quick Connect)

| Rule | Required |
|---|---|
| Name non-blank | **No** (defaults to trimmed host on accept) |
| Host / address / COM non-blank | Yes |
| Port `1..=65535` when set | Yes for SSH/RDP/VNC (`None` = protocol default). HTTP(S)/Serial hide the port box — stale values ignored / cleared on protocol switch |
| HTTP address usable host | Yes (IPv4/IPv6/DNS); serial COM line is **not** subject to this check |
| Serial baud `> 0` | Yes (inherit flags always false) |
| Serial data bits `5..=8` | Yes |
| RDP gateway / custom drives | Same as editor |

## Tunnel (optional)

- Seed: `TunnelEnabled = false` (No tunnel).
- Picker offers No tunnel / saved config only — Inherit always collapses to No tunnel on the QC API (getter and setter), independent of `allow_inheritance`.
- Serial: tunnel section hidden; selection forced off on write, `set_protocol`, and via `tunnel_selection` / `set_tunnel_selection`.

## Ephemeral accept path (parity)

1. Seed node (`seed_connection_node` / `QuickConnectState::new`)
2. User edits protocol + target (+ optional password / serial / HTTPS cert flag / tunnel / RDP tabs)
3. `try_build` → `QuickConnectResult { node, password }`
4. Caller resolves profile (`try_build_ephemeral_profile` / `prepare_connect`) and stores password in a process-local transient store keyed by `node.id` **or** passes it only via `ConnectOptions::password`
5. Open session tab / call `connect_prepared` / `connect_quick_connect` with `profile.is_ephemeral == true`

### Session orchestrator glue (`session_connect`)

Pure helper (no GPUI) that bridges QC accept → [`wormhole-session`](16-session-orchestrator.md):

- `prepare_connect(QuickConnectResult)` → solo `InheritanceResolver` + `is_ephemeral` + `ConnectOptions { password, .. }` (**resolver always before options**; solo map → no folder ancestry, dangling `parent_id` cannot invent tunnel/cred)
- `prepare_connect_ephemeral(profile, password)` → same packing when the profile is already resolved
- `connect_prepared` / `connect_quick_connect` → `SessionOrchestrator::connect`
- Happy path under Fake serial/SSH: SSH / Serial / HTTP / HTTPS
- RDP / VNC still fail closed with `SessionError::UnsupportedProtocol` (prepared request only; no OLE / VNC engine) — **before** any tunnel establish, so RDP+tunnel is never `TunnelArgsMissing`
- Tunnel **flags** (`tunnel_enabled` / `tunnel_config_id`) live on the ephemeral profile; `ConnectOptions::tunnel` args stay caller-owned (set before `connect_prepared`). `connect_quick_connect` does not load DPAPI tunnel secrets — SSH+tunnel without args → `TunnelArgsMissing`
- Callers that need the out-of-band password for a future RDP/VNC surface host should `prepare_connect` and branch **before** `connect_*` (orchestrator connect drops options)

Folder-level tunnel/cred inheritance for **persisted** tree Open is pinned in [17-tree-settings-vm.md](17-tree-settings-vm.md) / [02-domain.md](02-domain.md); QC writes concrete tunnel/cred on the ephemeral node (Inherit collapses to No tunnel / None).

Password is taken only for SSH / RDP / VNC when not using saved credentials. VNC never sets `use_inline_password` on the node (C# `WriteQuickConnectTo` + `TakeQuickConnectPassword`).

Redaction:

| Type | `Debug` / `Display` password |
|---|---|
| `QuickConnectResult` | Always `<redacted>` (hides Some/None) |
| `QuickConnectConnectRequest` | Always `<redacted>` on `options_password` / Display (parity with result; does not nest `ConnectOptions` Debug) |
| `ConnectOptions` | When present → `Some("<redacted>")`; when absent → `None` |

## Adversarial ledger

See [`adversarial-ledger-qc-history.md`](adversarial-ledger-qc-history.md) (recent-history MRU),
[`adversarial-ledger-qc-session-connect.md`](adversarial-ledger-qc-session-connect.md) (session glue),
[`adversarial-ledger-quick-connect.md`](adversarial-ledger-quick-connect.md) (full module), and
[`adversarial-ledger-quick-connect-delta.md`](adversarial-ledger-quick-connect-delta.md) (tunnel helpers / Debug / labels delta).

### Recent-history MRU (`history`)

Pure VM glue (no GPUI) for successful QC targets only — never passwords:

| API | Behaviour |
|---|---|
| `record_success` / `record_success_from_result` / `record_success_from_node` | Insert front; dedupe by protocol + case-insensitive trimmed host + port |
| Cap | [`DEFAULT_HISTORY_CAPACITY`] = 10 (truncate oldest); capacity `0` stays empty |
| `remove` / `remove_at` / `clear` | Persist-first commit (memory unchanged if store `save` fails); `remove` drops every matching key |
| Fail-closed | Blank / whitespace-only host → `EmptyHost`; list unchanged |
| Port normalize | Protocol defaults (`22`/`3389`/`80`/`443`/`5900`) collapse to `None` so implicit/explicit default dedupe; Serial always `None` |
| HTTP(S) | Stored as bare host + optional port (same as `ConnectionNode` after `write_to`); `apply_to_quick_connect` rebuilds `host[:port]` / `[ipv6]:port` |
| `FakeQuickConnectHistoryStore` | In-memory backend for unit tests / lab hosts |
| `apply_to_quick_connect` | Seed protocol / host / port on [`QuickConnectState`] (no creds / tunnel) |
| Load / `reload` | Sanitize blank hosts + duplicate keys, clamp capacity, persist when dirty |

Serial always stores `port = None`. Not wired to auto-record on `connect_quick_connect` yet — caller records after a successful session open.

Adversarial: [`adversarial-ledger-qc-history.md`](adversarial-ledger-qc-history.md).

## Non-goals

- GPUI Quick Connect chrome (title-bar stub remains until wired)
- Transient credential store / tab factory / dialog host
- Persisting ephemeral nodes to SQLite
- Durable history file / SQLite backend (Fake store only in this stub)
- Live RDP OLE / VNC engine from this glue (orchestrator stubs only)
- Loading tunnel secret blobs / `TunnelConnectArgs` inside `connect_quick_connect`

## Serial COM host-field glue

Shared with the connection editor: [`SerialPortPickerState`](../../rust/crates/wormhole-ui/src/serial_ports.rs) / `select_into_quick_connect` (see [20-connection-editor.md](20-connection-editor.md)). Refresh via `FakeSerialPortEnumerator` in tests; empty / enumerator-`Err` fail closed (`refresh_failed` only on `Err`; system soft-fail is `Ok([])`). Does not open the COM port. Adversarial: [adversarial-ledger-serial-picker.md](adversarial-ledger-serial-picker.md).

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-ui --no-default-features --lib history
cargo test -p wormhole-ui --no-default-features --features session --lib quick_connect
cargo test -p wormhole-ui --no-default-features --features session --lib
# Default features also pull tunnels OTP/SAML glue — use the flags above when that stream is mid-churn.
```

## Dependency

| Crate | Pin |
|---|---|
| `wormhole-domain` | workspace path |
| `wormhole-serial` | workspace path (COM list → Host; shared picker) |
| `wormhole-session` | workspace path via feature `session` (default; connect glue) |
| `uuid` | workspace (`v4` for seed ids) |
