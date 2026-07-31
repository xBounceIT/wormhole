# Adversarial ledger — RDP `RdpResolutionLayoutGlue`

Scope: `rust/crates/wormhole-surface-win/src/rdp/resize_glue.rs` (+ `rdp/mod.rs` exports), `docs/migration/05-rdp-spike.md` layout-glue notes, `docs/migration/native-surface-broker.md` references only  
Out of scope: live OCX / `UpdateSessionDisplaySettings` / HardwarePass; rewriting `ResolutionDebouncer` core beyond glue wiring  
Baseline: `cargo test -p wormhole-surface-win --features rdp` green (resize_glue + full crate)  
Design SoT: C# `RdpSurfaceHost.ApplyLayout` → `ScheduleResolutionRefresh` → `ApplyResolution`; `LAYOUT_RESOLUTION_MIN_DIM` = 8; Fake sink only

## Findings

| ID | Sev | Location | Issue | Evidence | Disposition |
|---|---|---|---|---|---|
| RG-001 | P2 | `resize_glue.rs` tests | NaN / ±∞ / negative / sub-min f64 fail-closed did not pin non-clobber of pending | Attack focus; only conversion asserts existed | **Fixed** — `nan_inf_f64_does_not_clobber_pending` + overflow / sub-min round asserts |
| RG-002 | P2 | `resize_glue.rs` tests | Connected reset only covered instant re-push; pending identical + poll path unpinned | C# clears `_lastNegotiated*` while debounce may still be armed | **Fixed** — `connected_reset_with_pending_identical_emits_on_poll` |
| RG-003 | P2 | `resize_glue.rs` tests | Glue flush↔poll coalesce race not pinned at Fake surface | Debouncer had it; glue `apply_count` could double-apply unnoticed | **Fixed** — `flush_then_poll_does_not_double_apply_surface` |
| RG-004 | P2 | `resize_glue.rs` tests | Cancel-on-drop only via `into_parts`; overdue whole-glue Drop untested | Attack focus; production drops glue, not parts | **Fixed** — Rc `FnMut` sink + overdue `drop(g)` |
| RG-005 | P3 | `resize_glue.rs` tests | Exact min-dim boundary (`8×8` ok / `8×7` reject) and seed non-clobber weak | Sub-min attack | **Fixed** — boundary + seed leaves pending `8×8` |
| RG-006 | P3 | `05-rdp-spike.md` | Layout glue semantics only one-liners in modules table | Parity with Resolution debounce table | **Fixed** — “Layout → debouncer → Fake resize glue” table |
| RG-007 | P3 | `on_layout_f64` docs / coalesce test | Fail-closed non-clobber undocumented; identical-size deadline restart unpinned | C# Stop/Start even when size unchanged | **Fixed** — doc note + `identical_size_still_restarts_quiet_deadline` |
| RG-008 | — | Clamp axes to `MAX_DESKTOP_AXIS` | Configure validates ≤16384 | Glue is layout coalesce only | **Rejected** — session/configure concern; matches RES-008 |
| RG-009 | — | Rewrite `ResolutionDebouncer` | Out of scope | User gate | **Rejected** — wire only |
| RG-010 | — | `min_dim as i32` wrap for huge test overrides | `with_min_dim(u32::MAX)` | `on_layout_size` still fail-closes | **Rejected** — test-only footgun; default is 8 |
| RG-011 | — | Merge poll/flush apply into helper / drop host early `is_degenerate` | Duplication taste | Parity with C# ApplyLayout skip-before-schedule | **Rejected** — clarify over micro-DRY |

## Fixes applied

- `rdp/resize_glue.rs` — attack-focus regressions (NaN non-clobber, connected+pending, flush↔poll surface, overdue Drop, min-dim boundary, identical deadline restart); `on_layout_f64` fail-closed docs
- `docs/migration/05-rdp-spike.md` — layout glue semantics table
- `docs/migration/README.md` — ledger link
- `wormhole-surface-win/src/lib.rs` — restored broken `//!` line that blocked `--features rdp` builds (unrelated doc corruption)

## Gate record

### Adversarial loop

| Cycle | Strategy | Accepted findings | Result |
|---|---|---|---|
| Adv-0 | Contract → boundary → state → concurrency → security → integration → perf → tests | RG-001…006 | Fixed; counter reset |
| Adv-1 | Same lanes on fixed tree; coalesce + f64 docs | RG-007 | Fixed; counter reset |
| Adv-2a | Contract→…→tests (post RG-007) | None | Clean (1/2) |
| Adv-2b | Reverse: tests-as-oracles → Drop/Fake → C# ApplyLayout / `_lastNegotiated*` → NaN non-clobber → no OCX → RG-008…011 hold | None | Clean (2/2) |

### Iterative-review-simplify (after adversarial clean)

| Cycle | Reuse | Efficiency | Quality/Bugs | Accepted | Result |
|---|---|---|---|---|---|
| Sim-1 | Shared `size()`; reject poll/flush helper / host early-check removal (RG-011) | No hot-path I/O; Fake `Vec` only on apply | Attack pins intact; fail-closed non-clobber | None | Clean (1/3) |
| Sim-2 | Exports via `rdp/mod.rs` only; no debouncer rewrite | Instant vs delayed paths unchanged | Drop field order cancel-before-surface; Connected reset does not cancel pending | None | Clean (2/3) |
| Sim-3 | Docs table matches code constants (`LAYOUT_RESOLUTION_MIN_DIM` = 8, 250 ms) | Reject micro on `is_pending()` after push | RG-008…010 remain rejected | None | Clean (3/3) |

No simplify edits → no adversarial re-loop required.

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-surface-win --features rdp
```

Result: **pass** — resize_glue unit tests (14) + full crate with `--features rdp`.

## Residual

- Live `ApplyDesktopSize` → `UpdateSessionDisplaySettings` remains deferred (`05-rdp-spike.md`).
- Pure debouncer review stays in [adversarial-ledger-rdp-resolution.md](adversarial-ledger-rdp-resolution.md); this ledger covers layout→Fake glue only.
