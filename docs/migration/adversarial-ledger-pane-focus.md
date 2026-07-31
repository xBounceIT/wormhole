# Adversarial ledger — pane focus glue (`pane_focus`)

**Scope (ONLY):**
- `rust/crates/wormhole-surface-win/src/pane_focus.rs` — `activate_pane` / `cycle_pane_focus` (+ `_bound`)
- WorkspaceState focus update; FocusCycle sync; FocusRequest for surface-bound / chrome handoff
- Docs: `docs/migration/08-ui.md`, `docs/migration/native-surface-broker.md` (pane focus sections)
- This ledger + `docs/migration/README.md` index

**Out of scope:** `BrokerPaneLayoutSink` tick path (untouched unless broken); HardwarePass / cutover; GPUI chrome; C#; FocusBroker Win32 apply path beyond request emission.

**Baseline (before review edits):** `cargo test -p wormhole-surface-win --features pane-layout -- pane_focus` — 8 ok; full `--features pane-layout` — 92 ok.

**Preserved invariants:** no Win32 in glue; no GPUI chrome; no layout-sink tick rewrite; empty / unknown fail-closed (workspace + cycle unchanged); request-only (caller applies via FocusBroker).

## Findings

| ID | Sev | Location | Issue | Evidence | Disposition |
|---|---|---|---|---|---|
| PF-001 | P1 | `sync_cycle_for_pane` / unbound path | Focus move to unbound pane left `FocusCycle` on previous surface | Attack: activate bound → activate unbound; cycle stayed `Surface(web)` while `WorkspaceState` focused unbound | **Fixed** — unbound sync sets chrome; emits chrome `FocusRequest` when leaving a surface |
| PF-002 | P1 | `activate_pane` early return | Idempotent path skipped cycle sync → rebind / late-bind under focused pane drifted | Attack: activate web → rebind to rdp → activate same pane; cycle stayed web | **Fixed** — always sync; emit only when `FocusRequest` before≠after |
| PF-003 | P2 | `08-ui.md` / `native-surface-broker.md` | Docs omitted unknown-pane fail-closed and unbound→chrome / repair semantics | Doc vs code | **Fixed** — docs updated + ledger link |
| PF-004 | P2 | tests | Missing regressions for bound→unbound, rebind, late-bind, Prev wrap, double activate | Attack list | **Fixed** — focused tests added |
| PF-005 | — | HWND map after sync | Speculative: activate should re-emit when `set_surface_hwnd` updates under current | Within one sync, before already includes new HWND → no delta | **Rejected** — out-of-band; callers use `request_for_current` + broker; pinned by test |
| PF-006 | P3 | broker appendix table | Related-ledgers appendix lacked pane-focus row | Index hygiene | **Fixed** — appendix + README index |
| PF-007 | P2 | tests | Same-`SurfaceId` kind refresh under focus unpinned | `insert_surface` refreshes kind; owner must change | **Fixed** — `idempotent_activate_repairs_same_id_kind_change` |
| PF-008 | P3 | `activate_unknown_pane_fail_closed` | Fail-closed did not assert cycle current preserved when already on a surface | Strengthened assertions | **Fixed** |
| PF-009 | — | FocusCycle ring membership | Rebind leaves prior surface id in ring | Tab ring may still list orphan until shell `sync_surfaces` | **Rejected** — membership owned by shell/broker sync; glue only sets **current** |
| PF-010 | — | PaneLayoutSink | Wiring change needed? | Grep: pane_layout untouched; `_bound` only reads `binding` | **Rejected** — in contract; stay untouched |
| PF-011 | — | Concurrent activate | Race on workspace/cycle | `&mut` exclusive | **Rejected** — impossible on same handles |
| PF-012 | — | Empty vs Unknown priority | `activate(empty, PaneId(9))` → EmptyLayout | Intentional fail-closed order | **Rejected** — empty checked first by design |

## Fixes applied

- `sync_cycle_for_pane`: always align cycle to binding (surface or chrome); emit `FocusRequest` iff before≠after
- Idempotent workspace activate still repairs cycle drift (rebind / late-bind / never-synced)
- Bound→unbound hands cycle to chrome (with chrome request when leaving a surface)
- Docs: unknown-pane fail-closed; repair vs out-of-band HWND; ledger links
- Regressions: empty/unknown, wrap Next/Prev, unbound↔bound, double activate, same-id kind, unbound-only cycle, HWND non-reemit, `_bound` chrome handoff

## Gate record

### Adversarial loop

| Cycle | Strategy | Accepted findings | Result |
|---|---|---|---|
| Adv-1 | Contract → boundary → state → concurrency → security → integration → perf → tests | PF-001…004 | Fixed; reset |
| Adv-2 | Reverse: tests → docs → kinds → fail-closed → sink wiring → HWND | PF-006…008; PF-005/009–012 rejected | Fixed; reset |
| Adv-3 | Forward lanes on post-fix glue | None | Clean (1/2) |
| Adv-4 | Reverse: feature flag, `_bound`, wrap, drift, docs claims, default no-pane-layout compile | None | Clean (2/2) |

### Iterative-review-simplify (after adversarial clean)

| Cycle | Reuse | Efficiency | Quality/Bugs | Accepted | Result |
|---|---|---|---|---|---|
| Sim-1 | `sync_cycle_for_pane` already central; `_bound` thin wrappers; empty-check kept on both entry points (public `activate` must fail-closed alone) | Dual `request_for_current` necessary for before/after | No further drift / fail-closed gaps | None (rejected: fold empty-check only into activate — cycle still needs len before index) | Clean (1/3) |
| Sim-2 | Test `map_resolve` local — keep | No hot-path I/O / alloc beyond cycle insert | HWND out-of-band pinned; PaneLayoutSink untouched | None | Clean (2/3) |
| Sim-3 | Docs/module/`FocusRequest` eq wording aligned | — | In-scope only; no GPUI/HardwarePass claims | None | Clean (3/3) |

No simplify implementation edits after Adv-4; three consecutive clean cycles completed with no code changes. Adversarial gate remains clean (no post-simplify reset required).

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-surface-win --features pane-layout -- pane_focus
cargo test -p wormhole-surface-win --features pane-layout
cargo check -p wormhole-surface-win
```

Result: **pass** — `pane_focus` filter **16** ok; `--features pane-layout` **100** ok; default `cargo check -p wormhole-surface-win` green (no `pane-layout`); `git diff --check` clean on touched paths.