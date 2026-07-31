# Adversarial ledger — Broker session surface glue (`session_surface`)

**Scope (ONLY):**
- `rust/crates/wormhole-surface-win/src/session_surface.rs` — `open_session_surface` / `close_session_surface` / `SessionSurfaceRegistry`
- Contracts: duplicate session / pane-in-use fail-closed; close idempotent unknown session; unknown surface dispose fail-closed
- Docs: `docs/migration/native-surface-broker.md`, `docs/migration/08-ui.md` (session surface notes)
- This ledger + `docs/migration/README.md` index

**Out of scope:** `BrokerPaneLayoutSink` tick internals (read-only use); `pane_focus` / `pane_split` (sibling glue); live HWND / WebView2 / COM; HardwarePass / gate-checklist; C#; `wormhole-tunnels`.

**Baseline (before review edits):** `cargo test -p wormhole-surface-win --features pane-layout` — 122 ok (8 `session_surface`); default `cargo check -p wormhole-surface-win` green.

**Preserved invariants:** Fake / `StubNativeSurfaceBroker` only; no GPUI chrome; no layout-sink tick rewrite; LabOnly (not HardwarePass).

## Findings

| ID | Sev | Location | Issue | Evidence | Disposition |
|---|---|---|---|---|---|
| SS-001 | P2 | `close_session_surface` | Registry `remove` before `unregister` dropped the session on any dispose error → non-`UnknownSurface` failures could not retry dispose | Attack: scripted `NotImplemented` on unregister; second close was idempotent `Ok` while Fake still listed the surface | **Fixed** — drop registry only on `Ok` or `UnknownSurface`; keep entry on other `SurfaceError` |
| SS-002 | P2 | tests | Register failure fail-closed (nothing tracked / unbound) unpinned | Hostile register `NotImplemented` | **Fixed** — `open_register_failure_fail_closed` + `ScriptedBroker` |
| SS-003 | P2 | tests | Close after external `unbind` (surface still live) unpinned | Attack: unbind then close must still `unregister` | **Fixed** — `close_after_external_unbind_still_disposes` |
| SS-004 | P2 | tests | Retryable dispose / pane-still-owned after failed close unpinned | Follow-on from SS-001 | **Fixed** — `close_retryable_surface_error_keeps_registry_then_succeeds` |
| SS-005 | P3 | tests | `session_surface` lookup / `session_for_pane`; close without prior layout | Coverage gaps | **Fixed** — lookup + `close_without_layout_still_unbinds_and_disposes` |
| SS-006 | P3 | docs / module | Retry-keeps-registry vs UnknownSurface-drops undocumented; ledger link missing | Doc vs close contract | **Fixed** — `native-surface-broker.md` / `08-ui.md` / module docs + appendix + this ledger |
| SS-007 | — | open vs sink-only binding | Out-of-band `register_and_bind` then open can orphan prior Fake surface | Misuse outside registry | **Rejected** — same class as pane-layout PL-013; PaneInUse is tracked-session only |
| SS-008 | — | concurrent open/close | Race on registry / sink | `&mut` exclusive on sink + registry | **Rejected** — impossible on same handles |
| SS-009 | — | handle moved to another pane | Close skips unbind on original pane, unregisters handle, leaves foreign binding | Out-of-band rebind across panes | **Rejected** — out of contract; same-pane rebind covered by `close_does_not_unbind_out_of_band_rebind` |
| SS-010 | — | HardwarePass / DPI | Doc claim risk | Text says LabOnly / Fake only | **Rejected** — no HardwarePass claim |

## Fixes applied

- `close_session_surface`: peek binding → unbind if ours → unregister; remove registry entry only for successful dispose or `UnknownSurface`
- Regressions: register fail-closed, external unbind then dispose, retryable unregister keeps registry + PaneInUse, lookup helpers, close without layout
- Docs: retry vs UnknownSurface semantics; LabOnly; ledger links in `08-ui.md` / `native-surface-broker.md` appendix

## Gate record

### Adversarial loop

| Cycle | Strategy | Accepted findings | Result |
|---|---|---|---|
| Adv-1 | Contract → boundary → state → concurrency → security → integration → perf → tests | SS-001…005 | Fixed; reset |
| Adv-2 | Reverse: tests → docs → kinds → fail-closed → sink wiring → feature flag → errors | SS-006; SS-007…010 rejected | Fixed; reset |
| Adv-3 | Forward lanes on post-fix glue | None | Clean (1/2) |
| Adv-4 | Reverse: feature flag, Fake kinds, races, docs claims, default no-pane-layout compile, error mapping | None | Clean (2/2) |

### Iterative-review-simplify (after adversarial clean)

| Cycle | Reuse | Efficiency | Quality/Bugs | Accepted | Result |
|---|---|---|---|---|---|
| Sim-1 | `session_surface` thin public alias kept; `ScriptedBroker` test-only | `session_for_pane` O(n) fine for stub; Entry API rejected (sink borrow) | Explicit Ok / UnknownSurface / other match arms kept | None | Clean (1/3) |
| Sim-2 | Duplicate-then-pane check order retained | No hot-path I/O | Retry vs UnknownSurface docs aligned | None | Clean (2/3) |
| Sim-3 | In-scope only; no tunnels / HWND churn | — | LabOnly claims intact | None | Clean (3/3) |

No simplify implementation edits after Adv-4; three consecutive clean cycles completed with no code changes. Adversarial gate remains clean (no post-simplify reset required).

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-surface-win --features pane-layout -- session_surface
cargo test -p wormhole-surface-win --features pane-layout
cargo check -p wormhole-surface-win
```

Result: **pass** — `session_surface` filter **14** ok; `--features pane-layout` **136** ok; default `cargo check -p wormhole-surface-win` green (no `pane-layout`).
