# Adversarial ledger — Tree filter / search id glue (`wormhole-ui`)

Scope (ONLY):
- `rust/crates/wormhole-ui/src/tree/filter.rs` (+ re-exports in `tree/mod.rs` / crate root)
- `ConnectionTreeModel` host/name match wiring (`tree/model.rs` → shared `fields_match_query_lower`)
- Related unit tests; `docs/migration/17-tree-settings-vm.md` filter section; README ledger link
- this ledger

Out of scope: GPUI TreeView; tree Open→session (`open.rs`); Quick Connect history (parallel stream — see note); display-cap / expand projection internals beyond host-match parity; drag-drop CRUD.

**Attack focus:** empty/whitespace = all; name **or** host match; ancestor folders; folder-name without subtree; phantom missing-parent ids; parent cycles; source load errors; `node_matches_query` casing footgun; filter↔model match drift; nested projection parity.

Baseline (before review edits): `cargo test -p wormhole-ui --lib tree:: --no-default-features` — 26 tests green.

## Findings

| ID | Sev | Location | Issue | Evidence | Disposition |
|---|---|---|---|---|---|
| TF-001 | P2 | `visible_connection_ids` ancestor walk | Missing `parent_id` inserted into intermediate visible set (phantom UUID) | Orphan match walk; set polluted though DFS omitted it | **Fixed** — only insert ancestors present in snapshot + regression |
| TF-002 | P2 | `node_matches_query` | Documented “pre-lowercased query” but public callers could pass mixed case → silent miss | `"PROD"` vs name `Prod` | **Fixed** — trim + lowercase inside; docs updated |
| TF-003 | P2 | `fields_match_query_lower` missing / model duplicate | `entry_matches_query_lower` duplicated name/host contract → drift risk | Side-by-side filter vs model | **Fixed** — shared helper; model delegates |
| TF-004 | P2 | `visible_connection_ids_from` | Source `list_all` failure unpinned | Attack: fail-closed Load | **Fixed** — `FailingConnectionSource` regression |
| TF-005 | P2 | `ordered_visible_ids` | Parent cycles (no root/orphan) dropped visible ids | A↔B + leaf match → empty Vec | **Fixed** — stable leftover append + regression |
| TF-006 | P2 | parity test | One-level child collect missed nested projection | Nested Mid→prod would false-pass | **Fixed** — recursive collect + nested fixture |
| TF-007 | P3 | trim / None host / empty snapshot | Contracts under-tested | Boundary lane | **Fixed** — trim, `host: None`, empty slice tests |
| TF-008 | — | Model cycle graphs still empty | Model indexes from roots only | Same as load projection | **Rejected** — expand/search VM is root-based; id-set API owns leftover |
| TF-009 | — | Rust `to_lowercase` ≠ C# `OrdinalIgnoreCase` | Locale / Turkish İ | Documented intentional | **Rejected** — parity note already in 17-tree-settings-vm |
| TF-010 | — | Filter has no 500-match cap | Differs from `ConnectionTreeModel` | Module docs | **Rejected** — thin id glue by design |
| TF-011 | — | Pass `by_id` into `ordered_visible_ids` | Double HashMap build | Efficiency | **Rejected** — churn for tiny snapshots; not measurable |

## Fixes applied

- Ancestor walk skips missing parents (no phantom ids); orphan matches still DFS-promoted
- `fields_match_query_lower` shared; `node_matches_query` trims/lowercases; model search uses shared helper
- Parent-cycle leftovers appended in SortOrder/Name/id order; `cmp_node_ids` centralizes sibling sort
- Direct matches collected as `Vec` (no `HashSet` clone before ancestor expand)
- Regressions: orphan phantom, failing source, casing API, None host, empty snapshot, trim, nested filter↔model parity, parent cycle
- Docs: filter table + public API in `17-tree-settings-vm.md`; this ledger + README index

## Gate record

### Adversarial loop

| Cycle | Strategy | Accepted findings | Result |
|---|---|---|---|
| Adv-1 | Contract → boundary → state → concurrency → security → integration → perf → tests | TF-001…007 | Fixed; reset |
| Adv-2 | Reverse: parity depth → trim → cycles → source errors → match footgun | TF-006 deepen + trim test | Fixed; reset |
| Adv-3 | Forward on post-fix surface (shared helper, leftover, exports) | None (TF-008…011 rejected) | Clean (1/2) |
| Adv-4 | Reverse: model host search, folder-without-subtree, empty=all, Debug/logging N/A | None | Clean (2/2) |

### Iterative-review-simplify (after adversarial clean)

| Cycle | Reuse | Efficiency | Quality/Bugs | Accepted | Result |
|---|---|---|---|---|---|
| Sim-1 | `cmp_node_ids` for sibling/orphan/leftover sorts; model → `fields_match_query_lower` | Drop `direct` HashSet clone → Vec | Docs API / orphan+cycle notes | Yes → reset | Fixed |
| Sim-2 | Shared match stays single | Skip double-`by_id` pass (TF-011) | In-scope only | None | Clean (1/3) |
| Sim-3 | Same | Same | No further churn | None | Clean (2/3) |
| Sim-4 | Same | Same | No further churn | None | Clean (3/3) |

### Post-simplify adversarial re-run (required)

| Cycle | Strategy | Accepted | Result |
|---|---|---|---|
| Adv-R1 | Delta: `cmp_node_ids`, Vec direct, shared match, leftover | None | Clean (1/2) |
| Adv-R2 | Reverse: phantom parent, cycle emit, model host parity, source Load | None | Clean (2/2) |

No further simplify edits after Adv-R*; simplify’s three clean cycles remain the last simplify run.

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-ui --lib tree:: --no-default-features
```

Result: **34 passed** (`tree::filter` + `tree::model`).

## Notes

- Unrelated parallel-stream compile break in `quick_connect/history.rs` (`sanitize_loaded` half-edited) was minimally restored so `wormhole-ui` could compile for verification; not part of this ledger’s acceptance surface.
- C# tree search remains name-only; Rust glue intentionally matches **host** as well (documented).
