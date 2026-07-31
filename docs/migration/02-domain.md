# Phase 2 — Domain crate (`wormhole-domain`)

**Status:** implemented (parallel with surface-lab; ordered ahead of gate wait)  
**Crate:** `rust/crates/wormhole-domain`  
**Source of truth:** C# `Data/InheritanceResolver.cs` + `Wormhole.Tests/Data/InheritanceResolver*.cs`

Pure Rust library: connection tree models, enum numeric values matching SQLite, and folder-level inheritance. No UI, no Win32, no storage I/O.

## Build / test

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-domain
```

Dependencies (workspace pins; Context7 MCP unavailable in this environment — same approach as `deps-pins.md`):

| Crate | Pin |
|---|---|
| `uuid` | `=1.24.0` (workspace; tests enable `v4`) |
| `thiserror` | `=2.0.19` |

## GUID format D

.NET `Guid.ToString("D")` / default `ToString()` → `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`.

Rust: `uuid::Uuid` hyphenated display and `wormhole_domain::format_guid_d(&id)` produce the same lowercase D form for storage-layer alignment later.

## Enum numeric map (must not drift)

| C# | Rust | Values |
|---|---|---|
| `ProtocolType` | `ProtocolType` | Ssh=0, Rdp=1, *(2 retired SFTP)*, Http=3, Https=4, Serial=5, Vnc=6 |
| `NodeKind` | `NodeKind` | Folder=0, Connection=1 |
| `CredentialBindingMode` | `CredentialBindingMode` | Inherit=0, None=1, Saved=2 |
| `CredentialKind` | `CredentialKind` | Password=0, SshKey=1 |
| `CredentialSecretProvider` | `CredentialSecretProvider` | Local=0, Bitwarden=1 |
| `SerialParityMode` | `SerialParityMode` | None=0 … Space=4 |
| `SerialStopBitsMode` | `SerialStopBitsMode` | One=1, Two=2, OnePointFive=3 |
| `SerialFlowControlMode` | `SerialFlowControlMode` | None=0 … DsrDtr=3 |
| `TunnelKind` | `TunnelKind` | WireGuard=0 … CiscoSecureClient=6 |

Each enum exposes `as_i32()` and `TryFrom<i32>` (error: `InvalidEnumValue`) so storage/import cannot invent a divergent discriminant map. Retired `ProtocolType` value `2` is rejected by `TryFrom`.

## Field map (`ConnectionNode` / `ConnectionProfile`)

C# PascalCase → Rust `snake_case` with identical nullability / tri-state semantics:

| C# | Rust |
|---|---|
| `Id` | `id` (`Uuid`) |
| `ParentId` | `parent_id` |
| `Name` | `name` |
| `Kind` | `kind` |
| `Protocol` | `protocol` |
| `Host` / `Port` / `Username` | `host` / `port` / `username` |
| `CredentialId` / `CredentialMode` | `credential_id` / `credential_mode` |
| `UseInlinePassword` | `use_inline_password` (leaf-only when resolving) |
| `Rdp*` | `rdp_*` |
| `Ssh*` | `ssh_*` |
| `Serial*` | `serial_*` |
| `HttpIgnoreCertErrors` | `http_ignore_cert_errors` (leaf-only) |
| `TunnelEnabled` | `tunnel_enabled` (`Option<bool>`: null inherit / false off / true on) |
| `TunnelConfigId` | `tunnel_config_id` |
| `ParentFolderName` (profile) | `parent_folder_name` |

`SerialDefaults` and `RdpScreenSizes` constants match C# (`Helpers/RdpScreenSizes.cs`, `Models/SerialSettings.cs`).

## Inheritance behavior (parity checklist)

- Walk leaf → root with `??=` / first-wins; explicit `false` beats ancestor `true`.
- Reject non-connection nodes; reject cycles; require resolved protocol + non-whitespace host.
- Cross-protocol port discard (port owner's governing protocol vs resolved protocol).
- Credential modes: Inherit / None / Saved + legacy null+CredentialId.
- Saved credential = identity boundary (no distant Username/RdpDomain mix-in).
- Inline password: SSH/RDP leaf-only; suppresses saved credential.
- Web + Serial: credential-less; clear SSH identity; Serial forces tunnel off.
- VNC: may keep password credential when protocol contexts match; drops username/SSH identity; inline password ignored.
- RDP defaults match mstsc-style profile defaults from C# resolver.

## Tests ported

| C# file | Rust file |
|---|---|
| `InheritanceResolverTests.cs` | `tests/inheritance_resolver_tests.rs` |
| `InheritanceResolverTunnelTests.cs` | `tests/inheritance_resolver_tunnel_tests.rs` |

Additional Rust-only pins (adversarial coverage): `tests/enum_parity_tests.rs`, `tests/domain_helpers_tests.rs`, `tests/inheritance_resolver_adversarial_tests.rs` (deep folder chains, null mid-folder tunnel tri-state, credential inherit/stop mid-chain, longer / protocol-lookup cycles), plus edge-case cases in the inheritance/tunnel suites (whitespace host, missing parent, empty map, self-cycle, Unicode names, protocol-agnostic port, credential Inherit ignoring own id, tunnel tri-state leaf overrides).

Pinned invariant (adversarial suite): `CredentialBindingMode::Saved` with a null `credential_id` stops credential inheritance but does **not** set the saved-credential identity boundary — ancestor `Username` / `RdpDomain` may still resolve.

xUnit `[Theory]` / `[InlineData]` cases are expanded to equivalent Rust `#[test]` functions or loops with the same assertions.

## Connect prepare call sites (do not bypass)

Tree Open and Quick Connect must run `InheritanceResolver` **before** attaching `ConnectOptions` (password / tunnel args). Never feed a raw leaf `ConnectionNode` to `SessionOrchestrator::connect`.

| Path | Crate | Snapshot | Notes |
|---|---|---|---|
| Tree Open / double-click | `wormhole-ui::tree::open` (`prepare_connect_request`) | Full `ConnectionNodeSource` map | Folder host / credential / tunnel tri-state inherit; folders fail closed; `is_ephemeral = false` |
| Quick Connect accept | `wormhole-ui::quick_connect::session_connect` (`prepare_connect`) | Solo ephemeral node | No folder ancestry; still resolves defaults (port, serial, …) before options |

See [17-tree-settings-vm.md](17-tree-settings-vm.md) and [21-quick-connect.md](21-quick-connect.md). Domain parity stays in this crate; glue pins live in `wormhole-ui` unit tests (`MemoryConnectionSource` / QC Fake).

## Connection node change notifier (Fake glue)

Pure pub/sub stub mirroring C# `IConnectionNodeChangeNotifier` / `ConnectionNodeChangeNotifier`, extended to **create / update / delete / reparent**. Lives in `wormhole-domain` (no GPUI, no SQLite).

| Type | Role |
|---|---|
| `ConnectionNodeChangeEvent` | Metadata-only: `node_id`, `NodeKind`, change kind, `parent_id` / `previous_parent_id` |
| `ConnectionNodeChangeKind` | `Created` / `Updated` / `Deleted` / `Reparented` |
| `ConnectionNodeChangeNotifier` | `publish` + `subscribe` / `unsubscribe` |
| `FakeConnectionNodeChangeNotifier` | Records events; fans out to callbacks **outside** the lock; nested publishes are queued until the current fan-out finishes (delivery order matches the event log) |
| `NopConnectionNodeChangeNotifier` | Swallow publishes (no listeners) |
| `RecordingRefreshListener` | Test helper: counts tree-reload vs session-profile-refresh hints |
| `*_from_node` helpers | Strip a `ConnectionNode` to metadata (C# update publish shape without cloning secret-bearing fields — domain rows never carry password bytes) |

Refresh hints:

- **Tree reload** — create / delete / reparent (`suggests_tree_reload`); update can patch in place (C# `ApplyConnectionNodeUpdated`). Structural parent moves must use **Reparented**, not Updated.
- **Session profile refresh** — update / delete / reparent (`suggests_session_profile_refresh`); folder mutations may affect descendant sessions (`may_affect_descendant_sessions`). Created is tree-only.

`FakeConnectionNodeChangeNotifier::clear` clears the recorded event log only (subscribers and in-flight nested publishes stay). Subscription ids wrap and skip `0` (reserved for Nop) and never collide with a live subscriber id.

**Never** put passwords, private keys, or tunnel payloads on the event. Storage / editor hosts publish after successful writes; tree + open-session VMs subscribe later (GPUI wiring Pending).

```powershell
cargo test -p wormhole-domain --test connection_node_change_tests
```

Adversarial review closed: [adversarial-ledger-node-change-notifier.md](adversarial-ledger-node-change-notifier.md).

## Deferred (out of scope for this crate)

- SQLite / Credential Manager / DPAPI persistence
- `ConnectionNode.Clone*` / `PendingInlinePassword` editor helpers
- Full `TunnelConfig` row + provider settings models
- `ConnectionProfileResolver` (repository wiring)
- UI / GPUI / surface-lab integration (tree + session subscribers over this Fake)
