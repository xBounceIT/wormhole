# Adversarial ledger — Tree reparent / drag validation glue (`wormhole-ui`)

Scope (ONLY):
- `rust/crates/wormhole-ui/src/tree/reparent.rs` (+ re-exports in `tree/mod.rs` / crate root)
- Related unit tests (incl. `--features storage` glue)
- `docs/migration/17-tree-settings-vm.md` reparent section; README ledger link
- this ledger

Out of scope: GPUI TreeView drag UX; full `PersistTreeStructureAsync` sibling reorder / folder-into-folder `UpdateMany` batch; storage `reparent_connection` internals (see [adversarial-ledger-folder-crud.md](adversarial-ledger-folder-crud.md)); `connection_node_change` pub/sub (domain); credential-picker UI.

**Attack focus:** search gate (validate + apply + drag); connection-as-parent; folder→descendant cycles; missing ids; multi-drag ancestor+descendant; Fake apply drift / noop / deleted node; source load errors; storage connection-only persist + noop; sort saturation.

Baseline (before review edits): `cargo test -p wormhole-ui --lib tree::reparent --no-default-features` — 10 tests green; `--features storage` — 11 green.

## Findings

| ID | Sev | Location | Issue | Evidence | Disposition |
|---|---|---|---|---|---|
| TR-001 | P2 | `apply_reparent_memory` | Trusted stale `ValidatedReparent` without cycle re-check | Drift: hang target under moved subtree, then apply → cycle | **Fixed** — re-`validate_reparent` on live Fake snapshot + regression |
| TR-002 | P2 | `apply_reparent_memory` | `is_noop` short-circuit skipped existence | Deleted node + noop handle → silent `Ok` | **Fixed** — validate runs before noop return + regression |
| TR-003 | P2 | `*_from` helpers | Source `list_all` failure unpinned | Attack: fail-closed `ReparentError::Source` | **Fixed** — `FailingConnectionSource` regression |
| TR-004 | P2 | `apply_reparent_memory` | Search not re-checked on apply | C# `PersistTreeStructureAsync` checks `IsSearchActive`; validate→search on→apply bypassed | **Fixed** — `options: ReparentOptions` on apply + regression |
| TR-005 | P2 | `apply_reparent_memory` return | Returned `()` left hosts with stale `old_parent_id` | Change-notifier would publish wrong previous parent after drift | **Fixed** — return fresh `ValidatedReparent` |
| TR-006 | P3 | tests / boundaries | Mid-chain cycle, empty drag+search, sort `i32::MAX`, storage noop, memory noop sort | Under-pinned contracts | **Fixed** — focused regressions |
| TR-007 | — | Drag with dangling `ParentId` | A+C may not reject if intermediate parent missing | Same as C# orphan/Children walk | **Rejected** — requires consistent snapshot; matches C# reachability |
| TR-008 | — | Duplicate ids in Fake slice | `HashMap` last vs `position` first | Hostile non-DB shape | **Rejected** — real `Nodes` PK unique |
| TR-009 | — | Share `next_sort_order` with storage | Duplicated saturating max+1 | Cross-crate coupling for Fake | **Rejected** — intentional local helper |
| TR-010 | — | Drop first validate in `reparent_memory` | Double validate under `&mut` | Defense for public apply path | **Rejected** — keep validate-then-apply clarity |

## Fixes applied

- `apply_reparent_memory(source, validated, options)` re-validates search/cycle/target/existence; mutates from **fresh** ids; returns fresh `ValidatedReparent`
- `reparent_memory` validates the live slice (no extra `list_all` clone) then apply
- `reparent_connection_storage` persists `validated.new_parent_id`; storage noop + folder/search paths covered
- Regressions: source load fail, stale cycle apply, deleted noop, search-on-apply, mid-chain cycle, empty drag+search, sort saturate, memory noop sort, storage noop
- Docs: reparent table in `17-tree-settings-vm.md`; this ledger + README index

## Gate record

### Adversarial loop

| Cycle | Strategy | Accepted findings | Result |
|---|---|---|---|
| Adv-1 | Contract → boundary → state → concurrency → security → integration → perf → tests | TR-001…003, TR-006 | Fixed; reset |
| Adv-2 | Reverse: C# Persist search → apply API → drag orphans → storage mapping | TR-004 | Fixed; reset |
| Adv-3 | Forward on post-fix apply surface | TR-005 | Fixed; reset |
| Adv-4 | Forward: options apply, fresh return, storage noop, mid-chain | None (TR-007…010 rejected) | Clean (1/2) |
| Adv-5 | Reverse: secrets/errors, exclusive `&mut`, sort saturate, empty drag | None | Clean (2/2) |

### Iterative-review-simplify (after adversarial clean)

| Cycle | Reuse | Efficiency | Quality/Bugs | Accepted | Result |
|---|---|---|---|---|---|
| Sim-1 | Keep local `next_sort_order` / test stubs | `reparent_memory` uses `source.nodes()` (no `list_all` clone) | Docs apply/`options` / ledger link | Yes → reset | Fixed |
| Sim-2 | Apply writes via `fresh.*` ids | Same | Stale-input vs fresh write clarity | Yes → reset | Fixed |
| Sim-3 | Double-validate kept (TR-010) | No further churn | In-scope only | None | Clean (1/3) |
| Sim-4 | Same | Same | No further churn | None | Clean (2/3) |
| Sim-5 | Same | Same | No further churn | None | Clean (3/3) |

### Post-simplify adversarial re-run (required)

| Cycle | Strategy | Accepted | Result |
|---|---|---|---|
| Adv-R1 | Delta: apply `options` + fresh return + slice validate + `fresh.*` write | None | Clean (1/2) |
| Adv-R2 | Reverse: search-on-apply, stale cycle, source Load, storage connection-only | None | Clean (2/2) |

No further simplify edits after Adv-R*; simplify’s three clean cycles remain the last simplify run.

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-ui --lib tree::reparent --no-default-features
cargo test -p wormhole-ui --lib tree::reparent --features storage
```

Result: **18 passed** (no-default-features); **20 passed** (`--features storage`).

## Notes

- Credential-picker (`credential_picker.rs`) intentionally untouched.
- Domain `connection_node_change` notifier is a sibling stream; hosts should publish metadata-only reparent events after successful glue writes (see [02-domain.md](02-domain.md)).
