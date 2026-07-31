# Connection editor state machine — `wormhole-ui`

**Status:** pure Rust state machine (no GPUI) + optional storage save glue  
**Date:** 2026-07-31  
**Crate module:** `wormhole_ui::connection_editor` (+ `persist` behind `--features storage`)  
**C# source of truth:** `ViewModels/ConnectionEditorViewModel.cs`, `Views/Dialogs/NewConnectionDialog.xaml(.cs)`, `ViewModels/TunnelPickerViewModel.cs`, `ViewModels/ConnectionTreeViewModel` SafeAdd/SafeUpdate + `ApplyInlineSecretAsync`

> Independent of GPUI chrome. Dialog rendering binds later; this spike owns validation,
> protocol-specific visibility, tunnel tri-state, credential mode, node round-trips, and
> (with `storage`) repository insert/update + out-of-band CredMgr password apply.

**Context7 MCP:** unavailable in this environment; pins follow workspace `Cargo.toml` / `deps-pins.md`.

## Scope

| Type | Role |
|---|---|
| `ConnectionEditorState` | Editable fields + `load_from` / `to_connection_node` / `write_to` / `apply_resolved_profile` |
| `ConnectionEditorMode` | `Persistent` (tree edit) vs `QuickConnect` (ephemeral) |
| `VisibleFields` | Protocol-driven chrome: port / creds / tunnel / RDP tabs / serial / HTTPS ignore-cert |
| `TunnelUiState` / `TunnelUiSelection` | Inherit / No tunnel / Config(id) — mirrors tunnel picker sentinels |
| `CredentialUiMode` | Saved picker vs inline/prompt (`UseSavedCredentials`) |
| `credential_picker` / `FakeCredentialList` | Metadata-only name/username(/domain) filter; empty query = all; no secrets in Debug |
| `ValidationReport` / `ValidationError` | Save-button gate |
| `save_validated_editor` / `load_inline_secret` / `EditorSaveOp` | Feature `storage`: validate → node → `ConnectionRepository` insert/update → CredMgr/`PasswordStore` (node Id); edit rehydrate |

Non-goals: Bitwarden catalog I/O, GPUI dialog chrome, experience-preset side effects on RDP speed changes, live WinCred in CI (use `FakePasswordStore`).

## Serial COM host-field glue

[`SerialPortPickerState`](../../rust/crates/wormhole-ui/src/serial_ports.rs) (crate root) lists ports via `wormhole-serial::SerialPortEnumerator` and writes the chosen name into editor / Quick Connect `Host` when protocol is Serial:

| Op | Behavior |
|---|---|
| `refresh(&dyn SerialPortEnumerator)` | Ok → replace list (clear `refresh_failed`); Err → clear list + `refresh_failed` (fail closed). System enumerator soft-fails OS errors as `Ok([])` inside `wormhole-serial`, so product refreshes do not set `refresh_failed`. |
| Empty list | Valid; selection returns `false` |
| `select_into_editor` / `select_into_quick_connect` | Index into Host; refuses non-Serial protocol and OOB index (`select_into_quick_connect` delegates to the editor path) |
| Live open | **Never** — enumerate only; session open stays in `wormhole-serial` / orchestrator |

Unit tests inject `FakeSerialPortEnumerator` (including `empty` / `failing`). GPUI combo chrome is still Pending.

## Serial baud / parity preset glue

[`serial_presets`](../../rust/crates/wormhole-ui/src/serial_presets.rs) maps PuTTY-style line presets ↔ editor / `ConnectionNode` serial fields (catalogs live in `wormhole-serial::presets`):

| Concern | Behavior |
|---|---|
| Defaults | **9600 8N1, flow None** (`SerialLineCombo::putty_defaults` / C# `SerialDefaults`) |
| Baud catalog | PuTTY Speed dropdown subset (`BAUD_RATE_PRESETS`); custom baud via `set_custom_baud` (C# NumberBox path) |
| Data / stop / parity / flow | Same labeled choices as `ConnectionEditorViewModel` combos |
| Fail closed | Non-Serial protocol, OOB preset index, or illegal Win32 DCB pairing (1.5 stop only with 5 data bits; 2 stop invalid with 5 data bits) — **no mutation** |
| Inherit | `write_editor_serial_to_node` writes `None` when inherit checkboxes are set; all-inherit skips DCB validate |
| Editor / QC | `validate()` rejects illegal DCB; `write_to` routes through preset glue (clears stale serial_* on illegal); QC `set_serial_*` delegates to `set_custom_*` |
| Open path | `SerialLineSettings::from_*` validates DCB after normalize (fail closed) |
| Live open | Preset glue itself never opens a port — value mapping only |

```rust
use wormhole_ui::{select_baud_preset, select_parity_preset, apply_putty_defaults_to_editor};
assert!(select_baud_preset(&mut state, 11)); // 115200
assert!(select_parity_preset(&mut state, 2)); // Even
```

## Visibility (parity checklist)

| Protocol | Port box | Creds | Tunnel | Host label | Extra |
|---|---|---|---|---|---|
| SSH | yes | yes | yes | Host | Auto sudo (unless SSH-key cred) |
| RDP | yes | yes | yes | Host | Display / Local Resources / Experience / Advanced |
| VNC | yes | yes | yes | Host | Password-only; username hidden |
| HTTP | no (address field) | no | yes | Address | — |
| HTTPS | no | no | yes | Address | Ignore cert errors |
| Serial | no | no | **no** | Serial line | Baud / data / stop / parity / flow; COM in Host |

## Validation matrix

| Rule | Persistent | Quick Connect | Notes |
|---|---|---|---|
| Name non-blank | required | optional | QC defaults name to target later |
| Host / address / COM non-blank | required | required | Serial still requires a COM line in `Host` |
| Port `1..=65535` when set | yes | yes | `None` = protocol default / inherit — **allowed**. Skipped for Serial and HTTP(S) (no port box) |
| HTTP address parseable host | yes | yes | Scheme/path stripped; `Uri.CheckHostName`-style check |
| Serial baud `> 0` when not inheriting | yes | yes | |
| Serial data bits `5..=8` when not inheriting | yes | yes | |
| Serial stop/data DCB pairing | yes | yes | Fail closed unless all serial fields inherit; see [`serial_presets`](#serial-baud--parity-preset-glue) |
| RDP gateway hostname when usage=Always | yes | yes | |
| RDP custom drive list well-formed | yes | yes | |

## Tunnel tri-state

Same semantics as domain / `TunnelPickerViewModel`:

- `Inherit` → `tunnel_enabled = None`, `tunnel_config_id = None`
- `NoTunnel` → `enabled = false`, config cleared
- `Config(id)` → `enabled = true`, config id set
- Serial write always forces `enabled = false` and clears config

Quick Connect disables inheritance (no Inherit sentinel; missing selection → No tunnel).

## Credential mode

- **Saved:** picker binding `Inherit` / `None` / `Saved(id)` → `CredentialBindingMode` + optional `credential_id`
- **Inline:** clears `credential_id`, sets `CredentialBindingMode::None`; SSH/RDP set `use_inline_password` and return pending plaintext from `to_connection_node` / `write_to` (never stored on `ConnectionNode`)
- Credential-less protocols (HTTP/HTTPS/Serial) clear credential fields on write

### Credential picker search glue

[`credential_picker`](../../rust/crates/wormhole-ui/src/credential_picker.rs) (crate root) ports C# `CredentialPickerSearch.Filter` — metadata-only rows + Fake list; **no GPUI**, no CredMgr reads:

| Op | Behavior |
|---|---|
| `filter_credential_profiles` / `filter_credential_profiles_from` | Empty / whitespace query → all rows (**stable input order**); else case-insensitive substring on **name** or **username** (plus **domain** for C# parity). `from` propagates source `Err` (no empty success invent) |
| `CredentialProfileRow` | `id` / `name` / `username` / `domain` only — **no** password / private-key / session fields; `Debug` cannot echo secrets |
| `FakeCredentialList` | In-memory `CredentialProfileSource` for tests; `Debug` is length + fail flag only; `set_profiles` clears any fail flag |
| `CredentialPickerSearchVm` | Cached snapshot + `set_query` → `filtered()`; successful `load_from` **replaces** snapshot (query unchanged); `load_from` `Err` keeps **last-good** cache + query (C# `LoadAsync` catch parity); no debounce (host may debounce); `Debug` uses counts / query length only |
| Secrets | Stay in CredMgr / DPAPI ([04-secrets.md](04-secrets.md)); this glue never loads secret material |

```rust
use wormhole_ui::{
    filter_credential_profiles, CredentialPickerSearchVm, CredentialProfileRow, FakeCredentialList,
};
let fake = FakeCredentialList::with_profiles([/* rows */]);
let mut vm = CredentialPickerSearchVm::new();
vm.load_from(&fake)?;
vm.set_query("alice");
let hits = vm.filtered();
```

Non-goals: SQLite credential-catalog repository, Bitwarden virtual rows, `ResolveExact` / commit helpers, GPUI combo chrome.

## Persist glue (`--features storage`)

Validated Persistent editor → `ConnectionRepository` insert/update, then CredMgr (or `FakePasswordStore`) keyed by **node Id**:

```rust
use wormhole_ui::{load_inline_secret, save_validated_editor, EditorSaveOp};
use wormhole_secrets_win::FakePasswordStore; // tests; production: WinCredPasswordStore

let mut state = /* validated Persistent editor */;
let repo = ConnectionRepository::new(&factory);
let passwords = FakePasswordStore::new();
let result = save_validated_editor(&mut state, &repo, &passwords, EditorSaveOp::Insert)?;
// result.stored.node has UseInlinePassword flag only — plaintext never on the row / Debug

// Edit path: after load_from, rehydrate chrome so rename/save does not purge CredMgr.
state.load_from(&result.stored.node, ConnectionEditorMode::Persistent);
load_inline_secret(&mut state, &passwords)?;
```

| Concern | Behavior |
|---|---|
| Validation | Fail closed before any SQLite / CredMgr write (`EditorSaveError::Validation`) |
| Quick Connect | Rejected (`EphemeralNotPersistable`) — ephemeral path stays in `21-quick-connect.md` |
| Insert id | Nil `editing_node_id` → assign `Uuid::new_v4()` before insert |
| Inline secret | After DB commit: non-empty pending → `PasswordStore::store(node.id, …)`; blank / leaving inline → `delete` (never store `""`) |
| Edit rehydrate | `load_inline_secret` after `load_from` (C# `LoadInlineSecretAsync`) — required so staying inline without clearing the field re-stores rather than deletes |
| Tree Duplicate | Sibling path in [17-tree-settings-vm.md](17-tree-settings-vm.md) (`build_duplicate` / `duplicate_connection`) — fresh node Id + cleared inline flag / fingerprint; **does not** copy CredMgr secrets; editor Insert is the path that stores a new inline password when the user types one |
| Editor chrome | Clears `inline_password` after successful apply; `Debug` still redacts |
| Partial failure | `Insert` + CredMgr failure → best-effort compensating `repo.delete` of the new row; chrome keeps plaintext for retry. `Update` + CredMgr failure keeps the committed row + chrome plaintext |
| Errors | `EditorSaveError` Display/Debug never embed secret material |

## Helpers

```rust
state.load_from(&node, ConnectionEditorMode::Persistent);
load_inline_secret(&mut state, &passwords)?; // feature = storage; after load_from when editing
let (node, pending_password) = state.to_connection_node();
state.apply_resolved_profile(&profile); // seeds Quick Connect from InheritanceResolver output
save_validated_editor(&mut state, &repo, &passwords, EditorSaveOp::Insert)?; // feature = storage

// Serial COM picker (no GPUI): Fake in tests / System in product — never opens the port.
use wormhole_ui::SerialPortPickerState;
use wormhole_serial::FakeSerialPortEnumerator;
let mut picker = SerialPortPickerState::new();
picker.refresh(&FakeSerialPortEnumerator::new(["COM1", "COM3"]));
picker.select_into_editor(0, &mut state); // requires ProtocolType::Serial

// Serial baud / parity presets (no GPUI): catalogs in wormhole-serial; fail-closed on illegal DCB pairs.
use wormhole_ui::{select_baud_preset, select_stop_bits_preset};
select_baud_preset(&mut state, 6); // 9600
```

`apply_resolved_profile` copies concrete profile values and forces Quick Connect mode (no inherit checkboxes).

## Build / test

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-ui --no-default-features --features storage
cargo test -p wormhole-ui --no-default-features --lib credential_picker
cargo test -p wormhole-ui serial_ports
cargo test -p wormhole-ui serial_presets
cargo test -p wormhole-serial
cargo test -p wormhole-storage
```

Focused suites:

- `tests/connection_editor_validation.rs` — per-protocol validation matrix, visibility, tunnel tri-state, credential modes, load/write round-trip, `apply_resolved_profile`, Debug redaction
- `tests/connection_editor_persist.rs` (+ `persist` unit tests) — temp DB insert/update round-trip, inline CredMgr Fake out-of-band, purge on leave-inline / blank, `load_inline_secret` preserve, Insert CredMgr rollback
- `credential_picker` unit tests — Fake list filter / empty query / name+username(+domain) match / Debug no secrets / `from` source `Err` / VM last-good on load `Err` / replace-not-append
- `serial_ports` unit tests — Fake enumerator refresh / empty / fail-closed / select into editor+QC host
- `serial_presets` unit tests — PuTTY defaults, preset index select, illegal stop/data fail-closed, node round-trip / inherit

Adversarial reviews:
- State machine: [adversarial-ledger-connection-editor.md](adversarial-ledger-connection-editor.md)
- Persist glue: [adversarial-ledger-editor-save.md](adversarial-ledger-editor-save.md)
- Credential picker search glue: [adversarial-ledger-credential-picker.md](adversarial-ledger-credential-picker.md)
- Tree Duplicate (sibling; no secret copy): [adversarial-ledger-tree-duplicate.md](adversarial-ledger-tree-duplicate.md)
- Serial enumerate library: [adversarial-ledger-serial-enumerate.md](adversarial-ledger-serial-enumerate.md)
- Serial COM picker glue: [adversarial-ledger-serial-picker.md](adversarial-ledger-serial-picker.md)
- Serial baud/parity presets: [adversarial-ledger-serial-presets.md](adversarial-ledger-serial-presets.md)

## Dependency

| Crate | Pin |
|---|---|
| `wormhole-domain` | workspace path |
| `wormhole-serial` | workspace path (COM enumerate → Host glue; PuTTY line presets / DCB validate) |
| `wormhole-storage` | workspace path (optional feature `storage`) |
| `wormhole-secrets-win` | workspace path (optional feature `storage` — `PasswordStore` / `FakePasswordStore`) |
| `uuid` | `=1.24.0` (workspace) |
| `thiserror` | `=2.0.19` (workspace; shell errors) |
| `tempfile` | workspace (dev) |
