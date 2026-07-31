# Adversarial ledger — Pane split/merge → BrokerPaneLayoutSink notify glue

**Scope (ONLY):**
- `rust/crates/wormhole-ui/src/layout_sink.rs` — `physical_updates_for_layout` / `notify_workspace_layout`
- `rust/crates/wormhole-surface-win/src/pane_split.rs` — `split_and_notify` / `merge_and_notify` / `split_with_and_notify` (+ `_bound`)
- Fail-closed `UiError` paths (`DuplicatePane`, `UnknownPane`, `PaneLimitReached`, `InvalidSplitRatio`, `LastPane`) with **no** layout tick
- Docs: `docs/migration/08-ui.md`, `docs/migration/native-surface-broker.md`
- This ledger + `docs/migration/README.md` index

**Out of scope:** `BrokerPaneLayoutSink` tick internals (read-only use; see [adversarial-ledger-pane-layout.md](adversarial-ledger-pane-layout.md)); `PaneLayout` / `WorkspaceState` core ops (see [adversarial-ledger-pane-split.md](adversarial-ledger-pane-split.md)); GPUI chrome; live HWND / WebView2 / COM; CredSSP / RDP wipe paths; C#; `wormhole-tunnels`.

**Impl:** `41371daf-70d8-427e-b5fa-d5913819acd4`

**Baseline (before review edits):** `cargo test -p wormhole-ui --no-default-features -- layout_sink` 6 ok; `cargo test -p wormhole-surface-win --features pane-layout -- pane_split` 8 ok; default `cargo check -p wormhole-surface-win` green.

**Preserved invariants:** Fake / Recording sinks only; notify **after** successful mutation; fail-closed skips tick; no PaneLayout core rewrite; LabOnly (not HardwarePass).

## Findings

| ID | Sev | Location | Issue | Evidence | Disposition |
|---|---|---|---|---|---|
| PSN-001 | P1 | `pane_split.rs` `merge_and_notify_bound` | Merge omit-hid via tick but left `PaneId`→surface binding; lowest-free-slot reuse resurrected the old surface Visible under the recycled id | Attack: bind 0+1 → split → merge 1 → split again allocates `PaneId(1)` → layout pushed to prior RdpActiveX | **Fixed** — unbind closed pane after successful merge, before notify; reuse regression |
| PSN-002 | P2 | `merge_and_notify` / docs | Unbound helper + broker sink footgun undocumented | Same reuse path if callers skip `_bound` | **Fixed** — rustdoc + `08-ui.md` / `native-surface-broker.md` prefer `_bound` / caller unbind |
| PSN-003 | P2 | tests | Unknown merge / fail-closed binding preserve / reuse unpinned | Attack lanes | **Fixed** — `merge_unknown_pane_fail_closed_no_tick`, `merge_bound_fail_closed_preserves_binding`, reuse test |
| PSN-004 | P2 | `layout_sink.rs` tests | Nested DFS≠insertion, odd width rounding, clamp-min column unpinned | Boundary / integration | **Fixed** — nested+odd, `SPLIT_RATIO_MIN` column, dpi/origin tests |
| PSN-005 | P3 | tests / docs | `split_with` success tick + NaN tree-literal walk + ledger missing | Coverage / policy | **Fixed** — success tick + NaN fallback test + this ledger + README |
| PSN-006 | — | `split_physical_bounds` `u32 as i32` | Extreme widths could truncate on cast | Multi-monitor / oversized content | **Rejected** — same class as pane-layout PL-012; chrome content rects are sane |
| PSN-007 | — | broker `update_bounds` Err after mutate | Glue still returns `Ok`; errors in `last_errors` | Soft sink contract | **Rejected** — matches `BrokerPaneLayoutSink` soft-error design |
| PSN-008 | — | unbound `merge_and_notify` + broker | Still omit-hide only | Documented footgun | **Rejected** — intentional thin API; `_bound` is the safe broker entry |
| PSN-009 | — | merge unbind without unregister | Orphan Fake surface until session close | Separation from `session_surface` | **Rejected** — dispose owned by session glue |
| PSN-010 | — | concurrent merge/notify | Race on sink | `&mut` exclusive | **Rejected** — impossible on same handles |

## Fixes applied

- `merge_and_notify_bound`: successful merge → `unbind(pane)` → notify survivors
- Docs/module contract: reuse-safe `_bound` vs omit-hide unbound helper
- Regressions: PaneId reuse, unknown/last fail-closed, nested/odd/clamp/dpi physical walks, `split_with` success tick, NaN tree-literal fallback
- Ledger + README index

## Gate record

### Adversarial loop

| Cycle | Strategy | Accepted findings | Result |
|---|---|---|---|
| Adv-1 | Contract → boundary → state → concurrency → security → integration → perf → tests | PSN-001…004 | Fixed; reset |
| Adv-2 | Reverse: docs → feature flag → errors → binding reuse → fail-closed → physical walk → exports | PSN-005 (+ doc/call-graph unbind notes) | Fixed; reset |
| Adv-3 | Forward lanes on post-fix glue | None (PSN-006…010 rejected) | Clean (1/2) |
| Adv-4 | Reverse: docs claims → default no-pane-layout compile → CredSSP untouched → LabOnly → error mapping | None | Clean (2/2) |

### Iterative-review-simplify (after adversarial clean)

| Cycle | Reuse | Efficiency | Quality/Bugs | Accepted | Result |
|---|---|---|---|---|---|
| Sim-1 | Do not fold `_bound` into unbound+post-unbind (notify order); thin split `_bound` alias kept | Per-tick `Vec` fine for Lab stub | Unbind-before-notify retained | None | Clean (1/3) |
| Sim-2 | `notify_bound_layout` typed wrapper kept | Unbind touches closed pane only; notify survivors | Fail-closed preserves bindings | None | Clean (2/3) |
| Sim-3 | In-scope only; no CredSSP / tunnels churn | — | LabOnly claims + diff hygiene | None | Clean (3/3) |

No simplify implementation edits after Adv-4; three consecutive clean cycles completed with no code changes. Adversarial gate remains clean (no post-simplify reset required).

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-ui --no-default-features -- layout_sink
cargo test -p wormhole-surface-win --features pane-layout -- pane_split
cargo test -p wormhole-ui --no-default-features
cargo test -p wormhole-surface-win --features pane-layout
cargo check -p wormhole-surface-win
```

Result: **pass** — `layout_sink` filter **10** ok; `pane_split` filter **12** ok; `wormhole-ui --no-default-features` green; `--features pane-layout` **140** ok; default `cargo check -p wormhole-surface-win` green (no `pane-layout`). CredSSP wipe file set untouched.
