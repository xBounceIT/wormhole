# Adversarial ledger — `TunnelConfigRepository` metadata CRUD

**Scope:** `rust/crates/wormhole-storage/src/repos/tunnel_config.rs`, `models::TunnelConfig`, temp-DB tests in `tests/storage_tests.rs`; docs [`03-storage.md`](03-storage.md) / [`07-tunnels-mcp.md`](07-tunnels-mcp.md).  
**Authority:** full adversarial-review-fix (edit in scope; do not stop at findings).  
**Baseline:** `cargo test -p wormhole-storage` green (prior storage + write-path ledgers closed).  
**Out of scope:** DPAPI tunnel payloads / live VPN; `HardwarePass` / cutover; editor ViewModel reference-check UI; `GetByTunnelConfigId` on `ConnectionRepository`.

## Gate status

| Gate | Result |
|---|---|
| Adversarial clean passes | **2** consecutive (independent attack order; post-simplify re-run also clean) |
| iterative-review-simplify clean passes | **3** consecutive |
| `cargo test -p wormhole-storage` | **pass** (24 unit + 38 integration; 1 ignored fixture generator) |

## Accepted findings and fixes

| ID | Sev | Location | Invariant | Evidence | Fix | Verification |
|---|---|---|---|---|---|---|
| TC-01 | P2 | `tunnel_config.rs` `insert` / `update` | Blank / whitespace-only names must not land in `TunnelConfigs` | C# validates in ViewModel only; repo accepted `""` / `"   "` | `require_nonblank_tunnel_name` trims + `InvalidArgument` | `tunnel_config_rejects_blank_name_on_insert_and_update` |
| TC-02 | P2 | `insert` + PK | Duplicate `Id` must fail closed | Untested PRIMARY KEY path | No code change (SQLite PK); regression | `tunnel_config_duplicate_id_insert_rejected` |
| TC-03 | P2 | `update` + `UX_TunnelConfigs_Name` | Rename onto an existing name must surface constraint error | Insert-dup covered; update-dup not | No code change (unique index); regression | `tunnel_config_update_duplicate_name_rejected` |
| TC-04 | P2 | `delete` + docs | In-use delete is **fail-open** at repo (no `Nodes.TunnelConfigId` check) | C# `DeleteAsync` same; editor refuses via `GetByTunnelConfigIdAsync` | Document fail-open in rustdoc + `03-storage` / `07-tunnels-mcp`; pin behavior | `tunnel_config_delete_succeeds_even_when_node_references_id` |
| TC-05 | P3 | `list_all` / `get_by_id` | Unknown `Kind` must fail closed on read | Only `list_all` asserted | Extend regression to `get_by_id` | `tunnel_config_rejects_unknown_kind_on_read` |

## Attack lanes (covered / residual)

| Attack | Disposition |
|---|---|
| Secret leakage into rows | **Covered** — schema 5 cols; INSERT uses `SELECT_COLUMNS`; round-trip asserts `pragma_table_info` count = 5 |
| `UpdatedAt` overwrite / auto-stamp race | **Covered** — `update` persists caller stamp verbatim; two-phase Name/Kind then bump tested |
| Unique name / SQL injection bindings | **Covered** — unique index + bound params; hostile name insert |
| Unknown `Kind` | **Covered** — `TunnelKind::try_from` on map; typed write API |
| Delete of in-use config | **Documented fail-open** (out of repo scope; editor owns) |
| Empty name | **Fixed** (TC-01) |
| Duplicate Id insert | **Covered** (TC-02) |

## Rejected / residual

| Candidate | Disposition |
|---|---|
| Fail `update`/`delete` when 0 rows affected | Rejected — C# `ExecuteAsync` same silent no-op |
| Reject `Uuid::nil` on insert | Rejected — C# `AddAsync` allows empty Guid |
| Case-insensitive unique names | Rejected — SQLite `UX_TunnelConfigs_Name` BINARY; C# same |
| Repo-layer in-use delete refusal | Rejected / out of scope — no FK; C# check lives in ViewModel; document fail-open |
| Share `parse_guid_col` / `require_nonblank_*` with `connection.rs` | Rejected — churn across write path; local helpers match folder pattern |
| Zero-width / exotic Unicode “blank” names | Rejected — speculative; `str::trim` covers White_Space |

## Simplify notes (post-adversarial)

- `INSERT` reuses `SELECT_COLUMNS` so metadata-only column list cannot drift from SELECT.
- Comment clarifies SELECT/INSERT vs UPDATE column sets.
- Three consecutive clean reuse / efficiency / quality cycles after that batch (no further validated edits).

## Adversarial clean cycles (final implementation)

1. **Pass A** (security → state/atomicity → contract → boundaries): param binding, metadata-only columns, verbatim `UpdatedAt`, blank-name / unique / unknown-kind / delete fail-open — no new accepted findings.
2. **Pass B** (integration drift → test resistance → concurrency → performance): C# `TunnelConfigRepository` parity, editor owns in-use check, one-connection-per-op, UNIQUE races — no new accepted findings.

Post-simplify re-run on INSERT/`SELECT_COLUMNS` delta: both orders clean again.

## iterative-review-simplify clean cycles

1. Reuse — INSERT via `SELECT_COLUMNS`; then clean.
2. Efficiency / quality (repos → tests order) — no further validated changes.
3. Docs / comment consistency — no further validated changes.

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-storage
```

**Result:** 24 lib + 38 integration passed; 1 ignored fixture generator.
