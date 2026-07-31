# Adversarial ledger — `wormhole-storage` write path + SettingsStore

**Scope:** `rust/crates/wormhole-storage/` — `ConnectionRepository` insert/update/delete*, `SettingsStore`, `AppSettings`; `docs/migration/03-storage.md` write/settings notes.  
**Authority:** full adversarial-review-fix (edit in scope; do not stop at findings).  
**Baseline:** `cargo test -p wormhole-storage` green (read-path ledger already closed).  
**Out of scope:** live `%LOCALAPPDATA%\Wormhole\wormhole.db` in CI; credential/tunnel repos; production WinUI cutover.

## Gate status

| Gate | Result |
|---|---|
| Adversarial clean passes | **2** consecutive (post-fix + post-simplify re-run) |
| iterative-review-simplify clean passes | **3** consecutive |
| `cargo test -p wormhole-storage` | **pass** (24 unit + 22 integration; 1 ignored fixture generator) |

## Accepted findings and fixes

| ID | Sev | Location | Invariant | Evidence | Fix | Verification |
|---|---|---|---|---|---|---|
| STORW-01 | P1 | `repos/connection.rs` `update_many` | Mid-batch FK failure must roll back prior updates | Happy-path test only; no hostile-parent rollback proof | Kept transactional `Connection::transaction`; added failure regression | `update_many_rolls_back_on_hostile_parent_id` |
| STORW-02 | P1 | `delete` + schema `ON DELETE CASCADE` | Nested folder delete must not leave orphan children | Only single-level cascade covered | Multi-level root→mid→leaf delete regression | `delete_folder_cascades_nested_children_no_orphans` |
| STORW-03 | P1 | `types.rs` `parse_guid_d` | GUID columns are format `D`; reject malformed / non-D | `Uuid::parse_str` / `try_parse` accepted format `N` | Shape check (36 + hyphens + hex) then `try_parse`; `InvalidGuid { message }` | `guid_d_rejects_malformed_and_non_d_forms` |
| STORW-04 | P1 | `settings.rs` migrate/save | Schema v8 migrate must not drop unknown JSON unsafely | Prior merge+struct drop lost forward-compat keys on persist | `#[serde(default)]` + `unknown_fields` flatten; single-parse load | `schema_migrate_preserves_known_and_unknown_fields` |
| STORW-05 | P2 | `settings.rs` path | Default settings path confined under `LOCALAPPDATA\Wormhole`; tests use temp | Untested | Assert `default_settings_path` under Wormhole; document `new` vs `default_local` | `default_settings_path_confined_under_wormhole_localappdata` |
| STORW-06 | P2 | `settings.rs` fail-closed | Bad enum / non-integer schema version → `CorruptSettings` | Untested beyond broken JSON | Regressions for `Theme: 99` and string schema version | unit tests |
| STORW-07 | P2 | write SQL | User strings must be bound params (no concat injection) | Attack lane; name not exercised | Hostile name insert still one row; table intact | `write_path_binds_hostile_name_without_sql_injection` |
| STORW-08 | P3 | docs | Writes/settings notes + ledger; no production cutover claim | Related docs pointed only at read ledger | `03-storage.md` write/settings notes; README + ledger link | doc review |

## Rejected / residual

| Candidate | Disposition |
|---|---|
| Fail `update`/`update_many` when 0 rows affected | Rejected — C# `ExecuteAsync` same silent no-op |
| Restrict `SettingsStore::new` to Wormhole/temp only | Rejected — DI/tests need arbitrary temp paths; production uses `default_local` |
| Atomic `settings.json` replace | Rejected — C# `File.WriteAllBytes` parity |
| Reject `Guid::nil` on insert | Rejected — C# `AddAsync` allows empty Guid |
| Generate `INSERT_PLACEHOLDERS` from column count | Rejected — churn without defect |
| Force `BitwardenCliServerRegion` only when unset on v7→v8 | Rejected — C# always sets `Current` for schema &lt; 8 |

## Simplify notes (post-adversarial)

- `InvalidGuid` uses `message: String` (no fake `uuid::Error` source).
- Settings load: one JSON parse via `parse_settings_document` (schema version + `AppSettings`).
- Clarified `SettingsStore::new` vs `default_local` path contract; minor `update_on` comment.

## Adversarial clean cycles (final implementation)

1. **Pass A** (security → state/atomicity → contract): SQL params, settings path/secrets, `update_many` rollback, cascade, GUID `D`, fail-closed — no new accepted findings.
2. **Pass B** (integration drift → boundaries → test resistance): C# `UpdateMany`/`DeleteMany`/`AppSettingsService` parity, hostile parent, malformed ids, schema unknown keys, docs non-cutover — no new accepted findings.

## iterative-review-simplify clean cycles

1. Reuse / efficiency / quality — applied InvalidGuid + single-parse; then clean.
2. `repos` → `types` → `settings` order — no further validated changes.
3. Tests/docs consistency — comment/docs only; clean.

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-storage
```

**Result:** 24 lib + 22 integration passed; 1 ignored fixture generator.
