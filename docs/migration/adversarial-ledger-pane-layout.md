# Adversarial ledger — BrokerPaneLayoutSink / pane-layout

Scope (ONLY):
- `rust/crates/wormhole-surface-win/` (`pane_layout`, `StubNativeSurfaceBroker` usage, feature `pane-layout`)
- `rust/crates/surface-lab/` pane-layout smoke (unchanged behavior; docs note only)
- `docs/migration/01-surface-lab.md`, `08-ui.md` notes for this feature
- `docs/migration/README.md` index link
- `wormhole-ui` `PaneLayoutSink` trait usage only as the implemented contract (no UI edits required)

Out of scope: C#; live HWND/COM hosts; hardware gate-checklist / DPI soak claims; unrelated crates.

Baseline (before review edits): `cargo test -p wormhole-surface-win --features pane-layout` 39 ok (7 pane_layout); `cargo check -p wormhole-surface-win` (default, no `pane-layout`) green.

## Findings

| ID | Sev | Location | Issue | Evidence | Disposition |
|---|---|---|---|---|---|
| PL-001 | P1 | `pane_layout.rs` `unbind` | Unbind left surface **Visible** at last rect (stale HWND overlay) | `unbind_stops_updates…` previously asserted Visible last update unchanged | **Fixed** — hide via `hide_surface` before dropping binding |
| PL-002 | P1 | `pane_layout.rs` `bind` | Rebind same `PaneId` to a new handle left previous surface Visible | Attack: WebView2 → RdpActiveX swap | **Fixed** — hide previous handle when `prev.id != handle.id` |
| PL-003 | P2 | bind / unbind timing | Bind-after-tick / unbind-between-ticks contracts untested | Attack focus race lane | **Fixed** — module contract + `bind_after_tick…` / unbind hide tests |
| PL-004 | P2 | `on_pane_layout` | Empty tick (all panes closed) untested | Hostile `[]` | **Fixed** — `empty_tick_hides_all_bound_surfaces` |
| PL-005 | P2 | degenerate path | Only width=0 covered; height=0 / extreme coords unpinned | Boundary lane | **Fixed** — height-zero + `i32::MIN/MAX` + dpi=0 hide tests |
| PL-006 | P2 | docs | Pane-layout smoke could be read as gate/DPI pass | Attack: doc claim | **Fixed** — `01-surface-lab.md` / `08-ui.md` explicitly **not** hardware gate / DPI soak |
| PL-007 | P2 | `unbind` | Missing-pane unbind cleared `last_errors` (diagnostic wipe) | `unbind(PaneId(9))` after unknown-surface error | **Fixed** — clear errors only after a binding is removed |
| PL-008 | P2 | `push_update` identical skip | PaneId-keyed skip after rebind could skip hide on **new** handle | Hide old → `last_pushed=Hidden` → omit new surface skipped | **Fixed** — clear `last_pushed` on handle change; `rebind_then_omit_still_hides_new_surface` |
| PL-009 | P3 | ledger / index | No adversarial ledger for this feature | README pattern | **Fixed** — this file + README link |
| PL-010 | — | NaN bounds | Adapter uses integer `PanePhysicalBounds` | No float NaN at this boundary | **Rejected** — chrome sanitizes floats before sink; integers cannot be NaN |
| PL-011 | — | mid-tick unbind | Concurrent unbind during `on_pane_layout` | `&mut self` exclusive | **Rejected** — impossible on same sink; between-tick unbind hides |
| PL-012 | — | clamp extreme `i32` | Off-screen coords when Visible | Multi-monitor legitimate | **Rejected** — hide only when degenerate; no panic path |
| PL-013 | — | dual-pane same `SurfaceHandle` | Caller binds one HWND to two panes | Misuse | **Rejected** — out of contract; soft last-writer wins |

## Fixes applied

- `BrokerPaneLayoutSink`: hide on unbind / rebind; clear push cache on handle change; identical-tick skip via `last_pushed`; soft no-ops for unbound / missing surfaces
- Regressions: degenerate axes, empty tick, bind-after-tick, unbind hide + SEED, rebind hide, rebind-then-omit, missing unbind preserves errors, identical omit skip
- Docs: no hardware gate-checklist / DPI soak claim for pane-layout smoke

## Gate record

### Adversarial loop

| Cycle | Strategy | Accepted findings | Result |
|---|---|---|---|
| Adv-1 | Contract → boundary → state → concurrency → security → integration → perf → tests | PL-001…006, 009 | Fixed; reset |
| Adv-2 | Reverse: feature flags → kinds → races → docs → errors → tests | PL-007 | Fixed; reset |
| Adv-3 | Forward lanes on post-fix sink | None | Clean (1/2) |
| Adv-4 | Reverse: skip cache, rebind, default feature, docs claims | None | Clean (2/2) |

### Iterative-review-simplify (after adversarial clean)

| Cycle | Reuse | Efficiency | Quality/Bugs | Accepted | Result |
|---|---|---|---|---|---|
| Sim-1 | Fold hide into `hide_surface`; `last_pushed` replaces `last_bounds` | Skip identical `SurfaceLayoutUpdate` | CountingBroker regression | Yes → reset | Fixed |
| Sim-2 | — | — | (post-sim adversarial found PL-008) | See Adv-R | — |

Sim interrupted by required post-simplify adversarial re-run (PL-008). After that fix, simplify restarted.

### Post-simplify adversarial re-run

| Cycle | Strategy | Accepted | Result |
|---|---|---|---|
| Adv-R1 | Delta: identical skip + rebind cache clear | PL-008 | Fixed; reset |
| Adv-R2 | Forward lanes on fixed skip/rebind | None | Clean (1/2) |
| Adv-R3 | Reverse: unbind/errors, empty tick, kinds, docs, default feature | None | Clean (2/2) |

### Iterative-review-simplify (restart after Adv-R fix)

| Cycle | Reuse | Efficiency | Quality/Bugs | Accepted | Result |
|---|---|---|---|---|---|
| Sim-A | Exhaustive `SurfaceKind` match kept (fail on new kinds) | Identical skip retained | No further bugs | None | Clean (1/3) |
| Sim-B | CountingBroker test-only — keep local | No hot-path I/O | Diff hygiene | None | Clean (2/3) |
| Sim-C | Docs/module contract aligned | — | In-scope only | None | Clean (3/3) |

No further simplify edits after Adv-R*; final simplify three clean cycles completed with no code changes.

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-surface-win --features pane-layout
cargo check -p wormhole-surface-win
cargo check -p surface-lab --features pane-layout
```

Result: **pass** — `wormhole-surface-win --features pane-layout` **78** tests (17 `pane_layout`); default `cargo check -p wormhole-surface-win` green (no `pane-layout`); `cargo check -p surface-lab --features pane-layout` green.
