# Adversarial ledger — `wormhole-storage`

**Scope:** `rust/crates/wormhole-storage/`, `rust/crates/wormhole-testkit/` (storage fixtures), `docs/migration/03-storage.md`, minimal `rust/Cargo.toml` glue only.  
**Authority:** adversarial-review-fix (edit in scope; do not stop at findings).  
**Baseline:** `cargo test -p wormhole-storage` green before review; C# refs `Data/MigrationRunner.cs`, `SqliteConnectionFactory.cs`, `SqliteTypeHandlers.cs`, `Repositories/ConnectionRepository.cs`.  
**Context7:** unavailable in this environment (noted; pins unchanged).

## Gate status

| Gate | Result |
|---|---|
| Adversarial clean passes | **2** consecutive |
| iterative-review-simplify clean passes | **3** consecutive |
| `cargo test -p wormhole-storage` | **pass** (9 unit + 12 integration; 1 ignored fixture generator) |
| `cargo test -p wormhole-testkit` | **pass** |

## Accepted findings and fixes

| ID | Sev | Location | Invariant | Evidence | Fix | Verification |
|---|---|---|---|---|---|---|
| STOR-01 | P1 | `migrate.rs` `embedded_migrations` | Embedded SQL must track `Data/Migrations/*.sql` | Hard-coded `include_str!` list could drift; only in-memory sort/count tested | `embedded_ids_match_on_disk_data_migrations` compares disk stems to embedded IDs | unit test |
| STOR-02 | P1 | `connection.rs` `SqliteConnectionFactory::open` | One connection per op on a durable file | `:memory:` / empty / `file:` URI each yield a distinct private DB per open | Reject those paths with `StorageError::Path` | unit + docs |
| STOR-03 | P1 | `repos/connection.rs` mapping | `TunnelEnabled` tri-state NULL/0/1 → `Option<bool>` | Untested inherit/off/on path | `tunnel_enabled_tri_state_maps_to_option_bool` | integration test |
| STOR-04 | P1 | `repos/connection.rs` `get_by_id` | Format `D` GUID lookup is case-insensitive | Uppercase Id in DB missed by lowercase `format_guid_d` bind (SQLite binary compare) | `WHERE Id = ?1 COLLATE NOCASE` | `uppercase_guid_round_trips_on_read` |
| STOR-05 | P2 | `connection.rs` open | Concurrent one-op opens should wait, not `SQLITE_BUSY` immediately | No busy timeout; MS.Data.Sqlite defaults ~30s | `busy_timeout(30s)` via `configure_connection` | `concurrent_opens_list_all` |
| STOR-06 | P2 | `connection.rs` / `migrate.rs` | `PRAGMA foreign_keys=ON` on every connection used for migrate/read | FK default is OFF; ParentId FK otherwise unenforced | `configure_connection`; also applied in `run_on` | `foreign_keys_enforced_on_parent_id` |
| STOR-07 | P2 | history / read path | Corrupt `AppliedAtUtc` must not block idempotent migrate; corrupt `CreatedAt` must fail read | Attack focus; previously untested | Regression tests for both | integration tests |
| STOR-08 | P2 | fixture + tests | Golden DB schema-only, no secrets; IDs match embedded | Weak fixture assertions | Stronger `open_golden_empty_schema_fixture` (ID parity, empty data tables, secret-needle scan) | integration test |
| STOR-09 | P2 | `repos/connection.rs` enums | Protocol/credential/serial map to domain; retired SFTP `2` rejected | Gaps in test resistance | `credential_mode_and_serial_enums_map`, `retired_sftp_protocol_value_rejected` | integration tests |
| STOR-10 | P3 | `types.rs` timestamps | `.NET O` round-trip includes fractional seconds | Test only compared whole seconds | Assert full `DateTime` + nanos equality; empty/garbage rejects | unit tests |

## Rejected / residual

| Candidate | Disposition |
|---|---|
| Port `GetByTunnelConfigIdAsync` | Rejected — documented out of scope for v1 read path |
| Treat empty-string optional GUIDs as `None` | Rejected — C# `Guid.Parse("")` fails; keep strict |
| Schema `COLLATE NOCASE` on `Nodes.Id` | Rejected — needs migration; writers emit lowercase `D` |
| Concurrent `MigrationRunner::run` serialization lock | Residual — same startup-serialized model as C#; documented in `03-storage.md` |
| Broad `list_*` SQL helper abstraction | Rejected — three call sites; `collect` enough |
| Path trim-on-open for padded paths | Rejected — speculative |

## Simplify notes (post-adversarial)

- Split `run` / `run_on` → shared `apply_pending` (avoid double pragma configure on factory path).
- Remove dead `format_rfc3339`.
- `execute_batch` error path uses `map_err` consistently.
- `list_all` / `list_by_kind` use `collect` instead of manual loops.

## Adversarial clean cycles (final implementation)

1. **Pass A** (security → concurrency → contract): path reject, bound migration params, FK, busy timeout, rollback, tunnel tri-state, disk sync — no new accepted findings.
2. **Pass B** (integration drift → boundaries → test resistance): C# column/enum parity, docs, fixture, corrupt timestamps, uppercase GUID, Protocol=2 — no new accepted findings.

## iterative-review-simplify clean cycles

1. Reuse / efficiency / quality — no further validated changes.
2. Same lanes, different file order (`repos` → `migrate` → `connection`) — clean.
3. Same lanes focusing on tests/docs consistency — clean.

## Verification commands

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-storage
cargo test -p wormhole-testkit
```
