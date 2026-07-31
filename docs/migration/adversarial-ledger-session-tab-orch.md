# Adversarial ledger — Session tab ↔ orchestrator glue

Scope (ONLY):
- `rust/crates/wormhole-session/src/id.rs` (`SessionId`)
- `rust/crates/wormhole-session/src/orchestrator.rs` `SessionHandle` id allocation (read + regression test)
- `rust/crates/wormhole-app/src/session_tabs.rs` (`open_tab_for_session`, `close_tab_on_session_closed`, UUID bit mapping)
- `rust/crates/wormhole-app/src/lib.rs` re-exports / feature gate for this module
- `docs/migration/08-ui.md` orchestrator-glue paragraph + `session_tabs` verify line
- `docs/migration/16-session-orchestrator.md` Session tab glue + verify / ledger links
- `docs/migration/README.md` index link
- this ledger

Out of scope: GPUI chrome / `TabStrip` wiring; live connect paths beyond `SessionHandle::id` uniqueness/Debug; `SessionTabBarState` internals (see [`adversarial-ledger-session-tabs.md`](adversarial-ledger-session-tabs.md)); HardwarePass / cutover.

**Attack focus:** Duplicate open fail-closed; close replay idempotent; UUID bit round-trip (nil / max / v4); wrong-type coercion = bits-only (no remap); empty / all-control titles soft-allowed; concurrent-ish pure-state reentrancy (background close, reopen-after-close); Debug secret leaks (none); doc/contract drift (`08` ↔ `16`).

Baseline (before review edits): `cargo test -p wormhole-session` — 32 ok; `cargo test -p wormhole-app --lib session_tabs` — 8 ok.

## Findings

| ID | Sev | Location | Issue | Evidence | Disposition |
|---|---|---|---|---|---|
| STO-001 | P2 | `session_tabs` tests | Empty / all-control titles through glue unpinned | Doc: empty allowed; only hostile non-empty covered | **Fixed** — `open_empty_title_allowed` |
| STO-002 | P2 | `id` / glue mapping tests | Round-trip only exercised `Uuid::nil()` | Attack: max / v4 / pub-field bits-only | **Fixed** — nil/max/v4 + `from_ui`↔`to_ui` loops in glue + `id.rs` |
| STO-003 | P2 | `session_tabs` tests | Reopen same id after close (and close replay → reopen) unpinned | Contract: Duplicate only while open | **Fixed** — `reopen_same_id_after_close_succeeds` |
| STO-004 | P2 | `session_tabs` tests | Background close / pure reentrancy unpinned | Close non-active must keep active | **Fixed** — `close_background_keeps_active` + `close_via_ui_round_trip_id` |
| STO-005 | P2 | `SessionHandle` / `id` | Handle id uniqueness + Debug password leak unpinned | Scope: allocation at connect start | **Fixed** — `session_handle_allocates_unique_stable_ids`; `debug_and_display_are_uuid_bits_only`; glue `session_id_debug_is_uuid_only` |
| STO-006 | P2 | `16-session-orchestrator.md` | Session tab glue section / `session_tabs` verify line drifted after parallel doc rewrite | `08-ui` still pointed at 16; 16 omitted glue body | **Fixed** — restored Session tab glue + verify command; ledger links |
| STO-007 | P3 | close match arms | `Ok` / `UnknownSession` split verbosity | Simplify reuse/quality | **Fixed** — `Ok(()) \| Err(UnknownSession(_))` |
| STO-008 | — | Unify orch/UI `SessionId` | Two newtypes | Integration lane | **Rejected** — intentional crate boundary; bit map via glue |
| STO-009 | — | BIDI / Cf in titles | Soft-handle = Cc only | Hostile unicode | **Rejected** — deferred with session-tabs ledger |
| STO-010 | — | Unbounded title length | Megabyte title | Perf | **Rejected** — pure state; cap at chrome |
| STO-011 | — | `Err(e)` arm unreachable today | `bar.close` only yields `UnknownSession` | Exhaustiveness | **Rejected** — keep for future `UiError` variants |

## Fixes applied

- Glue regressions: empty title, UUID bit matrix, reopen-after-close, background close, UI round-trip close, Debug UUID-only
- `SessionId` unit tests: nil/max/v4, Debug/Display free of password shape
- Orchestrator fake: unique/stable `SessionHandle::id` + Debug omits connect password
- Docs: restore `16` Session tab glue + `cargo test -p wormhole-app --lib session_tabs`; ledger index
- Simplify: collapse close idempotency match arms

## Gate record

### Adversarial loop

| Cycle | Strategy | Accepted findings | Result |
|---|---|---|---|
| Adv-1 | Contract → boundary → state → concurrency → security → integration → perf → tests | STO-001…006 | Fixed; reset |
| Adv-2 | Reverse: docs → Debug → reopen → empty title → UUID → fail-closed → handle id → badges | None (STO-008…011 noted) | Clean (1/2) — interrupted by simplify batch |
| Sim batch | Close match arm collapse (STO-007) | Code change | **Adversarial reset** |
| Adv-R1 | Reverse on post-simplify + doc restore | STO-006 (doc drift re-check) fixed before clean | Clean (1/2) |
| Adv-R2 | Forward lanes on final surface | None | Clean (2/2) |

### Iterative-review-simplify (after adversarial clean)

| Cycle | Reuse | Efficiency | Quality/Bugs | Accepted | Result |
|---|---|---|---|---|---|
| Sim-A | Parallel `SessionId` newtypes kept; close match already collapsed | No hot-path I/O | Unreachable `Err(e)` kept | None | Clean (1/3) |
| Sim-B | `to_ui_session_id` single helper | No alloc beyond title sanitize (UI crate) | Diff hygiene in-scope | None | Clean (2/3) |
| Sim-C | Docs `08`↔`16` aligned; feature gate `ui`+`session` | — | No HardwarePass claims | None | Clean (3/3) |

No further simplify edits after Adv-R*; final simplify three clean cycles completed with no code changes.

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-session
cargo test -p wormhole-app --lib session_tabs
```

Results at close: `wormhole-session` 33 passed; `wormhole-app --lib session_tabs` 13 passed.

**Not claimed:** HardwarePass / cutover.
