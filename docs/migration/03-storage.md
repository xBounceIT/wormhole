# Phase 3 — Storage crate (`wormhole-storage`)



**Status:** implemented (read + write path + settings JSON + TunnelConfig metadata CRUD + CredentialProfiles metadata CRUD)  

**Crate:** `rust/crates/wormhole-storage`  

**Source of truth:** C# `Data/MigrationRunner.cs`, `Data/SqliteConnectionFactory.cs`, `Data/SqliteTypeHandlers.cs`, `Data/Repositories/ConnectionRepository.cs`, `Data/Repositories/TunnelConfigRepository.cs`, `Data/Repositories/CredentialRepository.cs`, `Models/AppSettings.cs`, `Services/AppSettingsService.cs`, embedded `Data/Migrations/*.sql`



SQLite persistence + app settings JSON for the Rust migration. Uses **rusqlite** with the **bundled** SQLite feature. Does **not** change C# production behavior; SQL scripts are shared via `include_str!` from the existing `Data/Migrations/` tree.



## Build / test



```powershell

$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"

cd rust

cargo test -p wormhole-storage

```



Regenerate the schema-only golden fixture (optional):



```powershell

cargo test -p wormhole-storage --test generate_empty_schema_fixture -- --ignored --nocapture

```



Fixture path: `rust/crates/wormhole-testkit/fixtures/empty-schema.db` (no secrets / no real connection rows).



## Dependencies (workspace pins)



| Crate | Pin / note |

|---|---|

| `rusqlite` | `=0.40.1`, feature `bundled` |

| `chrono` | `=0.4.44` (clock + std) — `.NET O` timestamp text |

| `uuid` | workspace `=1.24.0` (+ `v4` for tests) |

| `serde` / `serde_json` | workspace — settings JSON (PascalCase) |

| `thiserror` | workspace `=2.0.19` |

| `wormhole-domain` | path — `ConnectionNode` / enums |

| `wormhole-testkit` | path — fixture paths (dev) |

| `tempfile` | workspace — temp-dir tests |



Context7 MCP was unavailable; pins follow the same crates.io research approach as `deps-pins.md`.



## Behavior parity with C#



| Concern | C# | Rust |

|---|---|---|

| Migrations | Embedded `Wormhole.Data.Migrations.*.sql`, alphabetical by id | `include_str!` of the same files; id = filename stem; `MigrationRunner::embedded()`; unit test asserts disk `Data/Migrations/*.sql` stems match |

| History table | `__migration_history (Id, AppliedAtUtc)` | Identical DDL + `INSERT` per pending migration inside a transaction |

| Apply time | `DateTime.UtcNow.ToString("O")` | `format_timestamp_o` (7 fractional digits + `Z`) |

| Connections | `ISqliteConnectionFactory.Open()` per op, `ForeignKeys=true` | `SqliteConnectionFactory::open()` + `PRAGMA foreign_keys = ON` + 30s busy timeout |

| Path contract | Connection string | Filesystem path only; rejects empty, `:memory:`, and `file:` URIs (private memory / URI modes break one-connection-per-op) |

| GUIDs | format `D` TEXT | `format_guid_d` / `parse_guid_d` (hyphenated `D` only; reject `N`/braced/URN); `get_by_id` / writers / deletes use `COLLATE NOCASE` |

| Timestamps | TEXT ISO / round-trip `O` | `parse_timestamp_o` accepts `O`, RFC3339, common Sqlite text forms |

| Nodes read | `GetAllAsync` order `ParentId, SortOrder, Name` | `ConnectionRepository::list_all` / `list_folders` / `list_connections` / `get_by_id` |

| Nodes write | `AddAsync` / `UpdateAsync` / `UpdateManyAsync` / `DeleteAsync` / `DeleteManyAsync` / `UpdateHostFingerprintAsync` | `insert` / `insert_many` / `update` / `update_many` / `delete` / `delete_many` / `update_host_fingerprint` — transactional for many; FK on; GUID `D` + timestamp `O`. UI callers: `wormhole-ui::save_validated_editor` / `load_inline_secret` (`--features storage`) validates Persistent editor state, writes via this repo, then applies inline passwords out-of-band through `wormhole-secrets-win::PasswordStore` keyed by **node Id** (see [`20-connection-editor.md`](20-connection-editor.md)); Insert CredMgr failure rolls back the new row |

| Folder CRUD | Tree VM `AddFolder` / edit / delete → repo | `create_folder` / `rename_folder` / `delete_folder` — Kind=Folder only; blank names rejected; parent must be folder; rows carry **no secrets**; parent check + `SortOrder` allocate + write use one `IMMEDIATE` transaction |

| Reparent stub | Drag-drop `PersistTreeStructureAsync` (full sibling rewrite) | `reparent_connection` — sets connection `ParentId` (+ append `SortOrder` in the same `IMMEDIATE` tx); rejects connection-as-parent so `InheritanceResolver` assumptions hold; full folder drag-reorder stays UI-side |

| Duplicate stub | Tree VM `Duplicate` → `CloneAsNewIdentity` + `AddAsync` | `duplicate_connection` — fresh Id, `"{name} (copy)"`, same parent, append `SortOrder`; clears fingerprint + inline-password flag; **never** copies CredMgr/DPAPI secret bodies; keeps shared credential/tunnel ids; folders → `InvalidArgument`; missing → `NotFound` |

| Parent delete | `ON DELETE CASCADE` | Same schema; deleting a folder removes descendants (`delete_folder` same cascade) |

| TunnelConfigs | `TunnelConfigRepository` — Id/Name/Kind/CreatedAt/UpdatedAt only; secrets DPAPI under `tunnels/` | `TunnelConfigRepository` — same columns; `insert` stamps both times; `update` persists caller `UpdatedAt` **verbatim** (no auto-stamp — TunnelManager pool invalidation); blank names rejected (`InvalidArgument`); `delete` is **fail-open** on in-use configs (no `Nodes.TunnelConfigId` check — editor owns that, matching C#) |

| CredentialProfiles | `CredentialRepository` — metadata only (Name/Username/Domain/Kind/…); passwords CredMgr; keys DPAPI | `CredentialRepository` + `credential_glue::{create,rename,delete}_credential_profile` — same columns; blank names fail-closed; Bitwarden field path blank/whitespace → `login.password`, non-blank trimmed (C# `NormalizeBitwardenFieldPath`); `delete` metadata fail-open on `Nodes.CredentialId` / `RdpGatewayCredentialId` (C# parity); optional [`CredentialSecrets`] / [`MemoryCredentialSecrets`] / `FakePasswordStore` cleanup **after** row delete (cleanup errors ignored) — **never** password bodies in SQLite |



## Settings JSON (`settings.json`)



| Concern | C# | Rust |

|---|---|---|

| Path | `%LOCALAPPDATA%\Wormhole\settings.json` | `default_settings_path()` / `SettingsStore::default_local()` (confined under `LOCALAPPDATA\Wormhole`); tests inject a temp path via `SettingsStore::new` |

| Shape | `AppSettings` schema **v8**, PascalCase, numeric enums | `AppSettings` + sibling enums; `serde` PascalCase; enums as `i32`; unknown JSON keys retained in `unknown_fields` across migrate/save |

| Missing file | Defaults in memory; no file until `Save` | Same |

| Corrupt JSON | **Fail open** (return defaults) | **Fail closed** — `StorageError::CorruptSettings` (intentional migration hardening) |

| Schema migrate | Bumps through v1…v8 (prompt, Bitwarden URLs/source/region, onboarding) | Same steps in `apply_schema_migrations`; best-effort persist after migrate; known fields preserved; unknown keys round-trip |

| Secrets | Never in this file (MCP token / passwords elsewhere) | Same — fixtures assert no secret needles |



Helpers: `SettingsStore::load` / `load_and_migrate` / `save`, `CURRENT_SCHEMA_VERSION = 8`.

**UI glue:** `wormhole-ui` (`--features storage`) exposes `StorageSettingsStore`, which implements the UI `SettingsStore` trait over this crate’s `SettingsStore`. `SettingsViewModel::stage` / `apply` / `reload` round-trip dirty edits through that adapter (temp-path tests). Unknown keys survive via shared `unknown_fields` flatten on both `AppSettings` shapes. Prefer one writer per `settings.json` path — see [17-tree-settings-vm.md](17-tree-settings-vm.md).



## Public API



```text

SqliteConnectionFactory::new(path) -> open() -> rusqlite::Connection

MigrationRunner::embedded() | with_migrations(vec) -> run(&factory) | run_on(&mut conn)

ConnectionRepository::new(&factory)

  -> list_all() / list_folders() / list_connections() / get_by_id(Uuid)

  -> insert(&ConnectionNode) -> StoredConnectionNode

  -> insert_many(&[ConnectionNode]) -> Vec<StoredConnectionNode>  (one transaction; parent-before-child; FK/PK failure rolls entire batch back — used by wormhole-import apply stub)

  -> update(&ConnectionNode) / update_many(&[ConnectionNode])

  -> delete(Uuid) / delete_many(&[Uuid])

  -> update_host_fingerprint(Uuid, &str)

  -> create_folder(name, parent_id) / rename_folder(id, name) / delete_folder(id)

  -> reparent_connection(connection_id, new_parent_folder_id)   // move stub

  -> duplicate_connection(source_id)   // connection-only; no secret bodies

  -> next_sort_order(parent_id)

StoredConnectionNode { node: wormhole_domain::ConnectionNode, created_at, updated_at }

TunnelConfigRepository::new(&factory)

  -> list_all() / get_by_id(Uuid)

  -> insert(id, name, kind) -> TunnelConfig   # stamps CreatedAt + UpdatedAt; trims name; rejects blank

  -> update(&TunnelConfig)                    # Name/Kind/UpdatedAt; caller supplies UpdatedAt; trims/rejects blank name

  -> delete(Uuid)                             # metadata only; fail-open if Nodes still reference Id

TunnelConfig { id, name, kind, created_at, updated_at }  # metadata only; no secret columns

CredentialRepository::new(&factory)

  -> list_all() / get_by_id(Uuid)

  -> insert(CredentialProfile) -> CredentialProfile   # stamps CreatedAt; trims name; rejects blank

  -> update(&CredentialProfile)                       # metadata fields; trims/rejects blank name

  -> delete(Uuid)                                     # metadata only; fail-open if Nodes still reference Id

credential_glue::create_credential_profile / rename_credential_profile / delete_credential_profile

  -> create from CredentialProfileDraft (no password arg)

  -> rename(id, name) fail-closed blank; NotFound if missing

  -> delete(id, Option<&dyn CredentialSecrets>)       # row first, then best-effort CredMgr/key cleanup

CredentialProfile { … metadata … }                    # no password field; Debug safe

MemoryCredentialSecrets                               # Fake/Memory cleanup stub (ids only; no bodies)

SettingsStore::new(path) | default_local()

  -> load() / load_and_migrate() / save(&AppSettings)

AppSettings (+ theme / auth / Bitwarden enums; `unknown_fields` flatten for forward-compat JSON)

default_app_data_dir() / default_settings_path()

format_guid_d / parse_guid_d / format_timestamp_o / parse_timestamp_o

```



`CreatedAt` / `UpdatedAt` stay on `StoredConnectionNode` because `wormhole-domain::ConnectionNode` intentionally omits persistence audit fields. `insert` stamps both; `update*` bumps `UpdatedAt` only.

`TunnelConfig` keeps timestamps on the row itself (C# model parity). `insert` stamps both; `update` does **not** auto-stamp — editors must bump `UpdatedAt` only after the DPAPI payload is on disk so `TunnelManager` does not cache a stale secret under a new stamp (see [`07-tunnels-mcp.md`](07-tunnels-mcp.md) edited-config invalidation).

`CredentialProfile` is metadata-only (C# parity). Passwords never enter this crate's write path — store/read/delete via `wormhole-secrets-win::PasswordStore` / `FakePasswordStore` keyed by **credential id**. Glue `delete_credential_profile` deletes the SQLite row first, then best-effort secret cleanup (same order as C# `CredentialsViewModel`).



## Out of scope (later)

- `GetByTunnelConfigId` (node reference sample for delete guards) and Bitwarden credential cache repository

- Credentials page UI — virtual catalog merge is lab-stubbed in `wormhole-secrets-win::bitwarden_credential_catalog` ([adversarial-ledger-bitwarden-catalog.md](adversarial-ledger-bitwarden-catalog.md)); GPUI picker wiring Pending

- DPAPI tunnel secret IO (lives in `wormhole-secrets-win`; not written by this repository)

- Inheritance (lives in `wormhole-domain`)

- Opening a live `%LOCALAPPDATA%\Wormhole\wormhole.db` in CI (use fixtures / temp dirs only)

- Concurrent `MigrationRunner::run` (same as C#: serialize at startup)

- C#-style fail-open for corrupt settings (Rust stays fail-closed)



## Related docs

- [`02-domain.md`](02-domain.md) — domain types consumed here  

- [`00-baseline.md`](00-baseline.md) — on-disk layout including `wormhole.db` / `settings.json`

- [`17-tree-settings-vm.md`](17-tree-settings-vm.md) — settings VM + `StorageSettingsStore` apply/persist glue

- [`20-connection-editor.md`](20-connection-editor.md) — `save_validated_editor` / `load_inline_secret` (wormhole-ui `--features storage`): validated Persistent editor → `ConnectionRepository::insert` / `update`, then CredMgr / `FakePasswordStore` keyed by **node Id** (plaintext never on the SQLite row; Insert CredMgr failure rolls back the new row)

- [`adversarial-ledger-editor-save.md`](adversarial-ledger-editor-save.md) — connection-editor → storage persist glue review closed

- [`adversarial-ledger-storage.md`](adversarial-ledger-storage.md) — storage read-path adversarial review ledger

- [`adversarial-ledger-storage-writes.md`](adversarial-ledger-storage-writes.md) — write path + SettingsStore adversarial review ledger
- [`adversarial-ledger-settings-apply.md`](adversarial-ledger-settings-apply.md) — UI SettingsViewModel → StorageSettingsStore apply glue ledger

- [`adversarial-ledger-folder-crud.md`](adversarial-ledger-folder-crud.md) — folder CRUD + connection reparent stub review closed

- [`adversarial-ledger-tunnel-config-crud.md`](adversarial-ledger-tunnel-config-crud.md) — TunnelConfig metadata CRUD review closed

