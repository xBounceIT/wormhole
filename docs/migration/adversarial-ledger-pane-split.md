# Adversarial ledger — PaneLayout split/merge

Scope (ONLY):
- `rust/crates/wormhole-ui/src/pane_layout.rs`
- `rust/crates/wormhole-ui/src/workspace.rs` (`WorkspaceState` wiring)
- `rust/crates/wormhole-ui/src/shell.rs` (`ShellState` split/merge/ratio + tab clear)
- `rust/crates/wormhole-ui/src/error.rs` (`DuplicatePane` / ratio errors)
- `docs/migration/08-ui.md` pane layout section
- `docs/migration/README.md` index link
- this ledger

Out of scope: GPUI chrome tiling math; `BrokerPaneLayoutSink` (see [adversarial-ledger-pane-layout.md](adversarial-ledger-pane-layout.md)); Quick Connect / session connect; C# production app.

**Attack focus:** NaN/±Inf reject (no silent coerce); ratios clamp `[0.15, 0.85]`; merge/split edge cases (last pane, unknown, nested promote, duplicates); flat `panes()` insertion order stable for broker / `PaneLayoutSink` (may diverge from DFS `leaves()`).

**Compatibility:** `PaneLayoutSink` trait + `PaneLayoutUpdate` / `PanePhysicalBounds` unchanged.

Baseline (before review edits): `cargo test -p wormhole-ui` — lib tests green (pane_layout / workspace / shell modules present with NaN + clamp coverage).

## Findings

| ID | Sev | Location | Issue | Evidence | Disposition |
|---|---|---|---|---|---|
| PS-001 | P1 | `pane_layout.rs` `split` | Public `split` allowed duplicate `new_pane` (incl. `== target`) → duplicate leaf ids / broken `leaf_count` semantics | Attack: `split(1, 0, …)` after `V(0,1)` succeeded | **Fixed** — `contains(new_pane)` → `UiError::DuplicatePane`; fail-closed regression |
| PS-002 | P2 | `workspace.rs` `panes()` | Insertion order vs DFS `leaves()` divergence unpinned; module comment conflated “insertion / DFS” | Nested split of first child → `panes=[0,1,2]`, `leaves=[0,2,1]` | **Fixed** — comment + `panes_insertion_order_stable_for_broker_when_dfs_diverges` |
| PS-003 | P2 | workspace / shell / pane_layout tests | ±Inf paths only partially covered (NaN-heavy); failed ops mutation not always asserted | Attack lane | **Fixed** — Inf through split/set_ratio; before/after snapshots on reject |
| PS-004 | P2 | `pane_layout.rs` merge | Multi-leaf sibling promote + unknown/last fail-closed weakly covered | Nested `V(H,H)` merge | **Fixed** — `merge_promotes_multi_leaf_sibling_subtree` + `merge_unknown_and_last_leave_tree_unchanged` |
| PS-005 | P2 | `shell.rs` `close_pane` | Last-pane failure clearing tab assignments untested (atomicity) | Attack: clear-before-close reorder | **Fixed** — `last_pane_close_does_not_clear_tab_assignment` |
| PS-006 | P3 | docs / rustdoc | Stale “NaN rejected” (omitted ±Inf); `leaves()` “tiling helpers” vs broker using `panes()` | Contract lane | **Fixed** — `08-ui.md` + API docs |
| PS-007 | P3 | ledger / README | No split/merge ledger | Policy | **Fixed** — this file + README link |
| PS-008 | — | `set_ratio_for_pane` | Quad root (both children splits) unreachable via immediate-parent API | Directed `V(H,H)` | **Rejected** — documented immediate-parent contract; chrome still uses coarse ratios |
| PS-009 | — | `WorkspaceState::close_pane` focus | List-neighbor focus vs tree-sibling merge hint | Divergent when DFS ≠ insertion | **Rejected** — intentional list-neighbor (comment); merge hint for tree callers |
| PS-010 | — | chrome `clamp_split_ratio` | Non-finite → 0.5 coerce | vs state machine reject | **Rejected** — documented; state machine does not coerce |
| PS-011 | — | `PaneLayout::Split { ratio: NAN }` struct literal | Bypass normalize | Misuse | **Rejected** — contract is ops / `normalize_ratio` |
| PS-012 | — | `DuplicatePane` vs `UnknownPane` precedence | `split(missing, existing_id)` → DuplicatePane | Both fail-closed | **Rejected** — uniqueness checked before target walk; acceptable |

## Fixes applied

- `UiError::DuplicatePane` + `PaneLayout::split` uniqueness guard
- Fail-closed NaN/±Inf + clamp boundary / signaling-NaN tests
- Nested merge promote + unknown/last regressions
- `panes()` insertion-order broker contract test + docs
- Shell last-pane tab-assignment atomicity test
- Misleading DFS/insertion comments; Inf called out in workspace/shell rustdoc
- Simplify: merge `collapse` takes sibling via `mem::replace` (no subtree clone)

## Gate record

### Adversarial loop

| Cycle | Strategy | Accepted findings | Result |
|---|---|---|---|
| Adv-1 | Contract → boundary → state → concurrency → security → integration → perf → tests | PS-001…007 | Fixed; reset |
| Adv-2 | Reverse: docs → sink compat → shell → workspace → tree → errors | PS-006 rustdoc Inf gaps | Fixed; reset |
| Adv-3 | Forward lanes on post-fix surface | None (PS-008…012 rejected) | Clean (1/2) |
| Adv-4 | Reverse: broker order → merge promote → duplicate → ratio reject → Shell clear | None | Clean (2/2) |

### Iterative-review-simplify (after adversarial clean)

| Cycle | Reuse | Efficiency | Quality/Bugs | Accepted | Result |
|---|---|---|---|---|---|
| Sim-1 | — | `collapse` clone → `mem::replace` take | — | Yes → reset | Fixed |
| Sim-2 | (interrupted — Adv-R required after impl change) | — | — | — | — |

### Post-simplify adversarial re-run

| Cycle | Strategy | Accepted | Result |
|---|---|---|---|
| Adv-R1 | Delta: merge take / placeholder drop by caller | None | Clean (1/2) |
| Adv-R2 | Reverse: Replace/Done paths, LastPane, panes↔leaves set equality | None | Clean (2/2) |

### Iterative-review-simplify (restart after Adv-R)

| Cycle | Reuse | Efficiency | Quality/Bugs | Accepted | Result |
|---|---|---|---|---|---|
| Sim-A | Take helper for 2 sites — reject (churn) | Take retained | List-neighbor focus kept | None | Clean (1/3) |
| Sim-B | `is_leaf` pub kept | ≤4 leaf allocs fine | Diff hygiene / Sink untouched | None | Clean (2/3) |
| Sim-C | Docs/API aligned | Double normalize micro-opt rejected | In-scope only | None | Clean (3/3) |

No further simplify edits after Adv-R*; final simplify three clean cycles completed with no code changes.

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-ui
# Focused:
cargo test -p wormhole-ui --lib -- pane_layout::
cargo test -p wormhole-ui --lib -- workspace::
cargo test -p wormhole-ui --lib -- shell::
```

Result: **pass** — focused pane_layout (13) + workspace (11) + shell (9) ok; full `cargo test -p wormhole-ui --lib` **124** ok. `PaneLayoutSink` surface not modified.

**Note:** During the run, an unrelated worktree `wormhole-import/Cargo.toml` had corrupted `CRCRLF` line endings that blocked cargo; normalized to LF so verification could proceed (outside feature scope).
