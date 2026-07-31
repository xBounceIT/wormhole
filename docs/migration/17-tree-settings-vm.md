# Connection-tree + settings view-models — `wormhole-ui`

**Status:** pure Rust view-models green (independent of GPUI chrome); tree Open→session glue stub; tree filter/search id glue stub; tree reparent/drag validation glue stub; tree duplicate connection glue stub; terminal font/size/auto-copy settings apply glue stub
**Date:** 2026-07-31  
**Crate:** `rust/crates/wormhole-ui` (`tree` + `settings` modules)  
**C# mirrors:** `ViewModels/ConnectionTreeViewModel.cs`, `ViewModels/SettingsViewModel.cs`, `Services/AppSettingsService.cs`, `Models/AppSettings.cs`

**Context7 MCP:** unavailable; pins from workspace `Cargo.toml` / `deps-pins.md`.

> **Not GPUI chrome / not a shipped TreeView:** shell layout lives in [08-ui.md](08-ui.md). This doc is the **Connections sidebar tree model** and **Settings JSON view-model** only — both compile without `--features gpui`. There is **no** GPUI `TreeView` binding and this workstream does **not** claim the connection tree UI is shipped in the GPUI shell.

## Scope

| Area | Type | Notes |
|---|---|---|
| Node source | `ConnectionNodeSource` | Trait — `list_all()` flat nodes |
| Memory source | `MemoryConnectionSource` | Unit tests / demos |
| Storage adapter | `StorageConnectionSource` | `--features storage` → `wormhole-storage` read API |
| Tree VM | `ConnectionTreeModel` | Load, search/filter projection, folder expand |
| Filter glue | `visible_connection_ids` / `visible_connection_ids_from` | Thin query → visible ids (name **or** host); ancestor folders kept |
| Reparent glue | `validate_reparent` / `should_reject_drag_selection` / `reparent_memory` / `reparent_connection_storage` | Drag/reparent validation (search, cycles, connection-as-parent); Fake apply; optional storage connection reparent |
| Duplicate glue | `build_duplicate` / `duplicate_memory` / `duplicate_connection_storage` | Same-parent connection copy (fresh Id, `" (copy)"` name, append SortOrder); folders rejected; no secret bodies; Fake + optional storage |
| Flatten | `flatten_visible()` | Depth-first rows respecting expand + search |
| Tree Open glue | `prepare_connect_request` / `prepare_tree_connect` / `connect_from_tree` / `connect_from_selection` | Double-click / Open / selection → `InheritanceResolver` → [`ConnectRequest`] / [`TreeConnectRequest`] + out-of-band [`ConnectOptions`] → `SessionOrchestrator::connect` (default feature `session`) |
| Settings model | `AppSettings` | PascalCase JSON, numeric enums (C# `System.Text.Json`) |
| Settings store | `SettingsStore` | Trait for load/save (coordinate writes without SQLite) |
| File store | `JsonFileSettingsStore` | `settings.json` under a `..`-free directory + schema migrate (fail-open on corrupt) |
| Memory store | `MemorySettingsStore` | Tests / injected host state |
| Storage settings | `StorageSettingsStore` | `--features storage` → wraps `wormhole-storage::SettingsStore` (fail-closed on corrupt) |
| Settings VM | `SettingsViewModel` | Immediate setters persist; `stage` / `apply` for dirty→apply→reload batch edits |
| Terminal display apply | `terminal_apply` → `wormhole_terminal::settings_apply` | AppSettings font/size/auto-copy → Lab apply messages / `FakeTerminalSettingsSurface`; empty font / non-positive size fail-closed |

### Connection tree behaviour (parity subset)

- Load flat `ConnectionNode` list → roots + children ordered by `SortOrder`, then `Name`.
- Orphan nodes (missing parent) are promoted to roots with the same stable sort.
- Case-insensitive **name or host** search (lowercase substring; C# `OrdinalIgnoreCase` name-only today — Rust glue also matches `Host`); projects matching paths only.
- Folder-name match shows the folder **without** forcing its subtree into the projection.
- Nested connection matches auto-expand ancestor folders; clearing search restores prior expand overrides.
- Display cap: [`MAX_DISPLAYED_SEARCH_MATCHES`] = 500 (status text when truncated; projection never exceeds the cap).
- Expand / collapse all; per-folder `set_expanded`.
- Reload preserves expand flags for surviving node ids.

### Tree filter / search id glue (`tree/filter.rs`)

Thin pure-state helper (no expand / no display cap — hosts that need projection use [`ConnectionTreeModel`]):

| Input | Output |
|---|---|
| Empty / whitespace query | Every node id, DFS (`SortOrder`/`Name`, orphans promoted) |
| Non-empty query | Ids whose **name** or **host** contains the query (case-insensitive), **plus** ancestor folder ids so nested hits stay reachable |
| Folder-name hit | Folder id only — unmatched children are **not** forced in |
| Missing parent | Orphan match kept; phantom parent id is **not** emitted |
| Parent cycles | Ancestors still collected; DFS leftovers appended in stable order |

`visible_connection_ids_from` loads via [`ConnectionNodeSource`] (tests use [`MemoryConnectionSource`]). No live DB required.

### Tree reparent / drag validation glue (`tree/reparent.rs`)

Thin pure-state helper mirroring C# `ShouldRejectDragSelection` + the validation subset of `PersistTreeStructureAsync` (no GPUI TreeView chrome). Distinct from credential-picker fields in `connection_editor`.

| Check | Behaviour |
|---|---|
| `ReparentOptions.search_active` | Reject validate / drag selection / Fake apply / storage apply (C# search disables drag-reorder; apply re-checks like `PersistTreeStructureAsync`) |
| New parent is a connection | `ReparentError::TargetNotFolder` (connections cannot contain children) |
| New parent is self or a descendant of the moved node | `ReparentError::WouldCreateCycle` (folder→descendant) |
| Missing node / missing parent | `ReparentError::NotFound` |
| Folder **or** connection move | Allowed at validate layer (C# `UpdateManyAsync` persists both) |
| Multi-drag ancestor+descendant | `should_reject_drag_selection` → `true` |
| Fake apply | `reparent_memory` / `apply_reparent_memory(…, options)` re-validate then mutate [`MemoryConnectionSource`] `ParentId` + append `SortOrder`; return fresh `ValidatedReparent` |
| Storage apply (`--features storage`) | `reparent_connection_storage` → `ConnectionRepository::reparent_connection` for **connections** only; folders → `FolderPersistUnsupported` after validate |

**Out of scope (later):** full drag-drop sibling reorder UX / `PersistTreeStructureAsync` folder-into-folder persist batch, add/edit/delete **commands** on the VM, inheritance host tooltips, debounce (host may debounce `set_search_text`), GPUI TreeView bindings.

**Storage write helpers:** `wormhole-storage::ConnectionRepository` exposes `create_folder` / `rename_folder` / `delete_folder`, `reparent_connection`, and `duplicate_connection` (temp-SQLite covered; see [adversarial-ledger-folder-crud.md](adversarial-ledger-folder-crud.md) / [adversarial-ledger-tree-duplicate.md](adversarial-ledger-tree-duplicate.md)). Tree glue validates first, then calls storage for connections; the tree model still reloads via `list_all`. See [03-storage.md](03-storage.md). After successful writes, hosts should publish metadata-only events on `wormhole-domain::FakeConnectionNodeChangeNotifier` (create/update/delete/reparent — no secrets) so tree + open-session subscribers can refresh; see [02-domain.md](02-domain.md).

### Tree duplicate connection glue (`tree/duplicate.rs`)

Thin pure-state helper mirroring C# `ConnectionTreeViewModel.Duplicate` + `ConnectionNode.CloneAsNewIdentity` (no GPUI). Distinct from connection-editor save (`save_validated_editor`) and reparent glue.

| Check | Behaviour |
|---|---|
| Missing source | `DuplicateError::NotFound` (fail closed) |
| Folder source | `DuplicateError::NotAConnection` (Lab rejects; C# Duplicate command silently no-ops) |
| Identity | `ConnectionNode::clone_as_new_identity` — fresh Id; clears `ssh_known_host_fingerprint`; `use_inline_password = Some(false)` |
| Placement | Same `ParentId`; name `"{name} (copy)"`; `SortOrder` = next sibling (saturating) |
| Secrets | **Never** copies CredMgr / DPAPI secret bodies into SQLite or Fake rows. Shared pool ids (`credential_id` / `rdp_gateway_credential_id` / `tunnel_config_id`) re-used by design |
| Fake apply | `duplicate_memory` / `apply_duplicate_memory` re-build against live snapshot then append; deleted source / id collision fail closed |
| Storage apply (`--features storage`) | `duplicate_connection_storage` → `ConnectionRepository::duplicate_connection` |

**Out of scope (later):** recursive folder duplicate, GPUI context-menu chrome, publishing change-notifier events inside glue (host responsibility).

### Tree Open / double-click → session (`tree/open.rs`)

Pure-state glue mirroring C# `ConnectionTreeViewModel.OpenConnectionAsync` for **persisted** tree nodes (no GPUI / no tab factory yet). Distinct from ephemeral Quick Connect [`session_connect`](21-quick-connect.md).

| Step | Behaviour |
|---|---|
| Lookup | `ConnectionNodeSource::list_all` → map by id; missing id → `TreeOpenError::NotFound` |
| Folder | Fail closed: `TreeOpenError::NotAConnection` (never calls the orchestrator). Selection path fails closed on `TreeNode.kind` before a source round-trip |
| Resolve | [`InheritanceResolver`](../../rust/crates/wormhole-domain/src/inheritance.rs) over the full snapshot; `is_ephemeral = false`. **Always before** any [`ConnectOptions`] (password / tunnel args) — never connect from a raw leaf node |
| Prepare | `prepare_connect_request` → [`ConnectRequest`] `{ profile }`; `prepare_tree_connect` / `prepare_tree_connect_from_selection` → [`TreeConnectRequest`] `{ profile, options }` with password on [`ConnectOptions`] only (`options_with_password` blank/whitespace → `None`) |
| Connect | `connect` / `connect_prepared` / `connect_from_tree` / `connect_from_selection` → [`SessionOrchestrator::connect`](16-session-orchestrator.md). CredMgr path: leave `options.password` empty and inject [`FakeCredentialResolver`] / host `CredentialResolver`. Protocol failures stay on [`SessionHandle`] (not `TreeOpenError`) |
| RDP / VNC | Orchestrator still fail-closed `UnsupportedProtocol` (typed prepare stubs); tree glue does not special-case |
| Inheritance pins (Fake `MemoryConnectionSource`) | Host inherit; folder tunnel on + config id; leaf `tunnel_enabled=false` skip (config id still inherits); folder Saved credential inherit; leaf `CredentialBindingMode::None` stops folder cred — all via `prepare_*` before options |

Unit tests use `MemoryConnectionSource` + Fake serial/SSH (+ optional Fake credential resolver): Serial / SSH / HTTP happy paths; RDP/VNC `UnsupportedProtocol`; folders / missing id / source / resolve errors never reach the orchestrator; folder tunnel/cred inheritance + inheritance skip; double-open; Debug redacts out-of-band passwords. Adversarial: [adversarial-ledger-tree-open-session.md](adversarial-ledger-tree-open-session.md). Domain resolver parity: [02-domain.md](02-domain.md).

### Settings behaviour

- `SettingsStore` trait stubs write coordination — JSON file IO is self-contained; prefer one writer per path.
- `JsonFileSettingsStore::in_directory` / `new` reject paths containing `..` and require the file name `settings.json`.
- Schema migrate mirrors C# `AppSettingsService.Load` (versions 1…8).
- Missing file → defaults. **Corrupt file:** `JsonFileSettingsStore` fails open (C# parity); `StorageSettingsStore` fails closed (`SettingsError::Corrupt`, storage semantics). Empty / whitespace-only / non-object roots fail closed on the storage path.
- VM setters for theme, confirm-on-close, updates, auto-copy, tunnel prompt, MCP enable/port, log retention, auth mode/fallback, sidebar width.
- Immediate persist: save failure rolls the in-memory document back (and preserves a prior `stage` dirty flag); `SettingsViewModel` Debug omits paths / error strings.
- Batch path: `stage(|s| …)` marks dirty without IO; `apply()` persists; `reload()` re-reads and clears dirty. Persist paths stamp `SettingsSchemaVersion` in memory and on disk to `CURRENT_SCHEMA_VERSION` (8).
- Unknown forward-compat JSON keys round-trip via `AppSettings::unknown_fields` (UI + storage shapes) so `StorageSettingsStore` apply does not strip them.
- No secrets in `settings.json` (MCP token / passwords stay elsewhere). Prefer one shared store instance per path (`&mut` VM; storage write lock on a single `Arc`).
- **Terminal font / size / auto-copy apply** (`settings/terminal_apply.rs`): maps `default_ssh_font` / `default_ssh_font_size` / `auto_copy_on_select` into `wormhole_terminal::TerminalSettingsConfig` → validate + typed Lab apply messages on `FakeTerminalSettingsSurface`. Empty / whitespace font (Unicode `trim`, including NBSP) and size ≤ 0 fail closed (Fake unchanged). Defaults share `DEFAULT_SSH_FONT_*` with the terminal crate. Auto-copy gate also rejects oversize selections (`MAX_SELECTION_UTF8_BYTES`). Live xterm options push still Pending — see [14-terminal-bridge.md](14-terminal-bridge.md).

## Public API

```text
ConnectionNodeSource::list_all() -> Result<Vec<ConnectionNode>, TreeError>
MemoryConnectionSource / StorageConnectionSource (feature = "storage")
ConnectionTreeModel::load_from / load_nodes / set_search_text / display_roots
  / display_children / set_expanded / expand_all / collapse_all / flatten_visible
visible_connection_ids(nodes, query) / visible_connection_ids_from(source, query)
node_matches_query(node, query) / fields_match_query_lower(name_lower, host_lower, query_lower)
validate_reparent / validate_reparent_from / should_reject_drag_selection[_from]
reparent_memory / apply_reparent_memory / ReparentOptions / ValidatedReparent / ReparentError
reparent_connection_storage (feature = "storage")
build_duplicate / build_duplicate_from / duplicate_memory / apply_duplicate_memory
BuiltDuplicate / DuplicateError / DUPLICATE_NAME_SUFFIX
duplicate_connection_storage (feature = "storage")

# feature = "session" (default):
prepare_connect_request(id, source) -> ConnectRequest
prepare_tree_connect / prepare_tree_connect_from_selection -> TreeConnectRequest
options_with_password / ConnectRequest::with_password|with_options
connect / connect_prepared / connect_from_tree / connect_from_selection
connect_tree / connect_tree_prepared (crate-root aliases) / TreeOpenError
fake_orchestrator_for_tests() / fake_orchestrator_with_credentials()

SettingsStore::load / save
JsonFileSettingsStore::in_directory / new (path-confined) / MemorySettingsStore
StorageSettingsStore::new / in_directory / default_local (feature = "storage")
SettingsViewModel::new / set_theme / set_* / stage / apply / save / reload
AppSettings (+ enums) — CURRENT_SCHEMA_VERSION = 8
terminal_settings_config_from_app / apply_terminal_settings_from_app
  / apply_terminal_settings_to_fake (+ re-exported FakeTerminalSettingsSurface)
```

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-ui reparent
cargo test -p wormhole-ui --features storage reparent
cargo test -p wormhole-ui --lib tree::duplicate --no-default-features
cargo test -p wormhole-ui --lib tree::duplicate --features storage
cargo test -p wormhole-storage duplicate_connection
cargo test -p wormhole-domain clone_as_new_identity
cargo test -p wormhole-ui terminal_apply
cargo test -p wormhole-terminal settings_apply
cargo test -p wormhole-ui
cargo test -p wormhole-ui --features storage
# Optional: tree Open + QC session glue off
cargo test -p wormhole-ui --no-default-features
# Optional (unchanged chrome — does not exercise the tree VM):
cargo test -p wormhole-ui --features gpui
```

## Coordination with storage-writes

- **Tree reads:** `ConnectionNodeSource` + optional `StorageConnectionSource` (`--features storage`) call `ConnectionRepository::list_all`. Node **writes** stay on the storage agent; tree reparent / duplicate glue may call `reparent_connection` / `duplicate_connection` after validate (`--features storage`).
- **Settings:** `SettingsStore` trait + `JsonFileSettingsStore` / `MemorySettingsStore` live in `wormhole-ui` so the VM is not blocked on storage. Prefer a single writer: inject `StorageSettingsStore` (`--features storage`) to drive `wormhole-storage::SettingsStore`, or use the UI file/memory backends alone — do not dual-write the same path. See [03-storage.md](03-storage.md).

## Related docs

- [08-ui.md](08-ui.md) — shell / panes / optional GPUI chrome
- [03-storage.md](03-storage.md) — SQLite read path consumed by `StorageConnectionSource`
- [02-domain.md](02-domain.md) — `ConnectionNode` / `NodeKind` / `clone_as_new_identity`
- [16-session-orchestrator.md](16-session-orchestrator.md) — protocol connect after resolve
- [20-connection-editor.md](20-connection-editor.md) — editor save vs tree Duplicate (sibling; no secret copy on Duplicate)
- [21-quick-connect.md](21-quick-connect.md) — ephemeral QC → session glue + recent-history MRU (sibling path; not the connection tree)
- [adversarial-ledger-tree-settings-vm.md](adversarial-ledger-tree-settings-vm.md) — adversarial review ledger
- [adversarial-ledger-tree-filter.md](adversarial-ledger-tree-filter.md) — tree filter/search id glue ledger
- [adversarial-ledger-tree-open-session.md](adversarial-ledger-tree-open-session.md) — tree Open → session connect glue ledger
- [adversarial-ledger-tree-reparent.md](adversarial-ledger-tree-reparent.md) — tree reparent / drag validation glue ledger
- [adversarial-ledger-tree-duplicate.md](adversarial-ledger-tree-duplicate.md) — tree duplicate connection glue ledger
- [adversarial-ledger-folder-crud.md](adversarial-ledger-folder-crud.md) — storage folder CRUD + `reparent_connection` stub
- [adversarial-ledger-settings-apply.md](adversarial-ledger-settings-apply.md) — SettingsViewModel → StorageSettingsStore apply glue ledger
- [14-terminal-bridge.md](14-terminal-bridge.md) — terminal font/size/auto-copy settings apply (`settings_apply` / Fake)
- [adversarial-ledger-terminal-settings-apply.md](adversarial-ledger-terminal-settings-apply.md) — terminal font/size/auto-copy settings apply glue ledger
