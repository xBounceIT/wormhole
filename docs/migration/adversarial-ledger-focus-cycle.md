# Adversarial ledger — FocusCycle (`wormhole-surface-win`)

**Scope:** `rust/crates/wormhole-surface-win/src/focus/cycle.rs` + FocusBroker integration patterns; `docs/migration/08-focus-a11y.md` FocusCycle section; README ledger link. Gate-7 FocusCycle smoke left as-is (already exercises chrome→WebView2→chrome via broker).  
**Authority:** adversarial-review-fix (edit in scope; do not stop at findings).  
**Baseline:** `cargo test -p wormhole-surface-win` green (51 tests) before review; 7 FocusCycle tests present.  
**Preserved FA invariants:** never `SetFocus(NULL)`; AutoReconnected skips by connect kind; latch only via `on_rdp_connected(ColdOrRetry)` on `Applied`; FocusCycle builds `FocusRequest` only — does not bypass `FocusBroker`.  
**Context7:** unavailable in this environment (noted; no dependency pin changes).

## Gate status

| Gate | Result |
|---|---|
| Adversarial clean passes | **2** consecutive (plus **2** re-loop after simplify) |
| iterative-review-simplify clean passes | **3** consecutive |
| `cargo test -p wormhole-surface-win focus::cycle` | **pass** (17 tests) |
| `cargo test -p wormhole-surface-win` | **pass** (61 tests) |

## Accepted findings and fixes

| ID | Sev | Location | Invariant | Evidence | Fix | Verification |
|---|---|---|---|---|---|---|
| FC-001 | P1 | `cycle.rs` `insert_surface` | Re-insert same `SurfaceId` with new kind must refresh `current` | Ring updated kind; `current` kept stale → wrong `FocusOwner` | Refresh via `refresh_current_surface_payload` | `insert_surface_duplicate_id_refreshes_kind_on_current` |
| FC-002 | P2 | `cycle.rs` `set_current` | Current surface payload must be ring-canonical | Caller could pass same id / wrong kind | Canonicalize from `surfaces` | `set_current_canonicalizes_kind_from_ring` |
| FC-003 | P2 | `set_chrome_hwnd` / `set_surface_hwnd` | Cycle must not store null HWND targets | `Some(FocusHwnd(0))` flowed into `FocusRequest` (broker still rejected) | Treat null as clear (`filter(!is_null)`) | `null_hwnd_not_stored_in_cycle` |
| FC-004 | P2 | tests | Attack lanes unpinned: duplicate insert, remove non-current, peek, broker-only apply, empty sync | Test resistance | Focused regressions | listed below |
| FC-005 | P3 | `08-focus-a11y.md` | Doc claimed sync_from_broker “stable id order” | Survivors keep prior ring order; only newcomers / first populate are id-sorted | Clarified FocusCycle section; lab partial unchanged | doc review |
| FC-006 | P2 | tests | `sync_surfaces` kind refresh / empty clear untested after helper extract | State lane | `sync_surfaces_refreshes_kind_on_current`, `sync_surfaces_empty_clears_to_chrome_only` | unit tests |

## Rejected / residual

| Candidate | Disposition |
|---|---|
| Cycle should call `FocusBroker` internally | Rejected — stub API builds `FocusRequest`; shell/lab applies via broker (matches FA-010 prefer-broker pattern) |
| `set_surface_hwnd` for unknown id is orphan | Rejected — intentional pre-bind before insert; sync retain cleans |
| Allocate-free `peek` without `slots()` Vec | Rejected — stub; readability > micro-alloc |
| Merge overlapping broker integration tests | Rejected — different contracts (apply path vs no hidden SetFocus) |
| Gate-7 smoke expand for remove/sync | Rejected — unit coverage sufficient; smoke already broker-wired |
| Docs claim AccessKit/UIA hardware gates 7–8 passed | Not present — status remains Lab partial; “Status vs pass” intact |

## Fixes applied

- `focus/cycle.rs` — current-payload refresh helper; canonicalize `set_current`; null HWND filtered; Prev wrap `(idx + len - 1) % len`; `sync_surfaces` single HashMap collect
- `focus/mod.rs` — FocusCycle docs: no Win32 / no broker bypass
- `docs/migration/08-focus-a11y.md` — FocusCycle wrap/sync/null/broker wording + ledger link
- `docs/migration/README.md` — ledger entry (removed duplicate focus-a11y row while inserting)

## Gate record

### Adversarial loop

| Cycle | Strategy | Accepted findings | Result |
|---|---|---|---|
| Adv-0 | Contract → boundary → state → concurrency → security → integration → perf → tests | FC-001…005 | Fixed; reset |
| Adv-1 | Tests-as-oracles → security → state → contract → boundaries | FC-006 | Fixed; reset |
| Adv-2a | Full lanes forward | None | Clean (1/2) |
| Adv-2b | Reverse: docs honesty → FA latch parity → peek wrap → cfg(windows) stub sync | None | Clean (2/2) |

### Iterative-review-simplify

| Cycle | Reuse | Efficiency | Quality/Bugs | Accepted | Result |
|---|---|---|---|---|---|
| Sim-fix | — | Prev index branch → modular wrap | — | **Fixed** | Reset |
| Sim-fix | Drop intermediate sync Vec | Single HashMap collect | Dup-id last-wins documented | **Fixed** | Reset |
| Sim-1 | `refresh_current_*` shared; keep `slot_eq` (id-only) | Fine | Invariants intact | None | Clean (1/3) |
| Sim-2 | No apply-through-broker helper | Fine | Docs/FA conflict check | None | Clean (2/3) |
| Sim-3 | Tests pin attack focus | Fine | Lab partial ≠ hardware pass | None | Clean (3/3) |

### Adversarial re-loop (after simplify)

| Cycle | Strategy | Accepted | Result |
|---|---|---|---|
| Adv-R1 | Delta: Prev wrap + sync HashMap; empty/chrome-only; null filter | None | Clean (1/2) |
| Adv-R2 | Reverse: never SetFocus from cycle; latch untouched; remove/sync current drift | None | Clean (2/2) |

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-surface-win focus::cycle
cargo test -p wormhole-surface-win
```

Result: **pass** — 17 FocusCycle unit tests; 61 crate tests; `git diff --check` clean on touched paths.

## Deferred

- Production shell Tab/Shift-Tab wiring of FocusCycle → FocusBroker
- Hardware evidence packs for gate-checklist 7–8 (unchanged; not claimed here)
