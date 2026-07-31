# Adversarial ledger — folder / connection tree CRUD

**Scope:** `rust/crates/wormhole-storage/` — `ConnectionRepository::{create_folder, rename_folder, delete_folder, reparent_connection, next_sort_order}`; kind guards; blank names; cascade delete; no secrets on folder create rows; `InheritanceResolver` `ParentId` walk after reparent; docs [`03-storage.md`](03-storage.md) / [`17-tree-settings-vm.md`](17-tree-settings-vm.md); temp-SQLite tests.  
**Authority:** full adversarial-review-fix (edit in scope; do not stop at findings).  
**Baseline:** `cargo test -p wormhole-storage` green; inheritance suites green.  
**Out of scope:** HardwarePass / production cutover; full drag-drop sibling reorder (`PersistTreeStructureAsync`); CredMgr GC on cascade; GPUI tree chrome.

## Gate status

| Gate | Result |
|---|---|
| Adversarial clean passes | **2** consecutive (independent orders; re-run after simplify code edits) |
| iterative-review-simplify clean passes | **3** consecutive |
| `cargo test -p wormhole-storage` | **pass** (24 unit + 40 integration; 1 ignored fixture generator) |
| Inheritance resolver tests | **pass** (61 + 15 adversarial + 5 tunnel) |

## Accepted findings and fixes

| ID | Sev | Location | Invariant | Evidence | Fix | Verification |
|---|---|---|---|---|---|---|
| FC-01 | P2 | `repos/connection.rs` `create_folder` / `reparent_connection` | Parent Kind check + `next_sort_order` + write must not race on sibling max | Separate opens; concurrent creates could share `SortOrder` | Single `IMMEDIATE` transaction; shared `next_sort_order_on` / `require_folder_on` | `concurrent_create_folder_assigns_distinct_sort_orders` |
| FC-02 | P2 | `next_sort_order_on` | Hostile/migrated `SortOrder = i32::MAX` must not wrap | `m + 1` overflow | `saturating_add(1)` | `next_sort_order_saturates_at_i32_max` |
| FC-03 | P2 | tests + rename/delete/create | Missing ids → `NotFound`; Unicode / ideographic blank; fuller no-secrets | Attack lanes under-tested | Expanded `folder_crud_*` + `assert_folder_row_has_no_secrets` | `folder_crud_create_rename_delete_temp_sqlite` |
| FC-04 | P2 | `reparent_connection` + inheritance | Append under non-empty parent; detach must break old inherit chain | Sort assumed 0; root detach only checked `ParentId` | Sibling pre-seed → sort 1; resolve → `MissingHost` after root detach | `reparent_connection_stub_updates_parent_and_inheritance_chain` |
| FC-05 | P3 | docs `03-storage.md` | Folder CRUD / reparent note must match `IMMEDIATE` + append semantics | Doc lag after tx fix | Table rows updated | doc review |

## Rejected / residual

| Candidate | Disposition |
|---|---|
| `UNIQUE(ParentId, SortOrder)` schema | Rejected — C# allows duplicates; `ORDER BY SortOrder, Name` tie-breaks |
| CredMgr / DPAPI cleanup on folder cascade | Rejected — out of scope; C# delete same (node rows only) |
| Reject zero-width-only / BOM-only names | Rejected — speculative; `trim()` matches Unicode White_Space / C# `IsNullOrWhiteSpace` parity for blanks |
| Folder-into-folder / full drag reorder | Rejected — stub explicitly defers to UI `PersistTreeStructureAsync` |
| Reparent cycle via connection children | Rejected — connections cannot be parents via these helpers; self-parent rejected |
| Fail `update` when 0 rows affected | Rejected — generic write path C# parity (prior storage-writes ledger) |

## Simplify notes (post-adversarial)

- `rename_folder` / `reparent_connection` return in-memory `StoredConnectionNode` after write (no redundant re-SELECT).
- `get_by_id` reuses `get_by_id_on`.
- Concurrent test drops unused path `Arc`.

## Adversarial clean cycles (final implementation)

1. **Pass A** (security → state/atomicity → contract → boundaries): no-secrets create, IMMEDIATE allocate+write, kind guards, blank/Unicode, cascade — no new accepted findings.
2. **Pass B** (integration drift → concurrency → test resistance → performance): docs IMMEDIATE note, concurrent distinct sorts, inheritance after move/detach, NotFound paths — no new accepted findings.

## iterative-review-simplify clean cycles

1. Reuse / efficiency / quality — applied re-fetch removal + test cleanup; adversarial re-loop then clean.
2. Efficiency → quality → reuse — no further validated changes.
3. Quality → reuse → efficiency (docs/tests consistency) — clean.

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-storage
cargo test -p wormhole-domain --test inheritance_resolver_tests --test inheritance_resolver_adversarial_tests --test inheritance_resolver_tunnel_tests
```

**Result:** storage 24 lib + 40 integration passed; inheritance 81 passed; no HardwarePass / cutover claimed.
