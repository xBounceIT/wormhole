# Adversarial ledger — RDP `ResolutionDebouncer`

Scope: `rust/crates/wormhole-surface-win/src/rdp/resolution.rs` (+ `rdp/mod.rs` exports), `docs/migration/05-rdp-spike.md` debounce notes only  
Out of scope: CredSSP / configure / password wipe paths  
Baseline: `cargo test -p wormhole-surface-win --features rdp` green (resolution module + full crate)  
Design SoT: C# `RdpSurfaceHost` (`ResolutionDebounceMs = 250`, `_resolutionTimer` stop on Unloaded), `docs/migration/native-surface-broker.md`

## Findings

| ID | Sev | Location | Issue | Evidence | Disposition |
|---|---|---|---|---|---|
| RES-001 | P2 | `resolution.rs` `flush` | Empty `flush`/`poll` with stale `due_at` left deadline set (`pending.take()?` returned before clear) | Invariant break if pending/due diverge; poll would keep calling empty flush | **Fixed** — clear `due_at` before taking pending |
| RES-002 | P2 | `resolution.rs` tests | Attack-focus contracts under-pinned: flush↔poll double-emit, overdue Drop/Apply, `Default` 250 ms, degenerate non-clobber, `i32::MIN` / zero physical, saturating deadline | Prior `cancel_on_drop` never exercised overdue pending; flush-on-drop would commit `last_emitted` without failing sink asserts | **Fixed** — expanded regression tests + Drop contract comment |
| RES-003 | P3 | `05-rdp-spike.md` | Debounce semantics (cancel-on-drop, zero skip, instant, no Connect) only one-liners | Spike doc vs C# Unloaded timer stop | **Fixed** — dedicated “Resolution debounce (pure logic)” table |
| RES-004 | P2 | `05-rdp-spike.md` | Debounce subsection split the Rust modules markdown table (orphan rows) | Table header closed mid-list after first edit | **Fixed** — modules table restored; debounce section after |
| RES-005 | — | Debouncer skip sizes `< 8` (C# `IsDegenerate()` default) | ApplyLayout skips before schedule; ApplyResolution only rejects `< 1` | C# surface host | **Rejected** — caller / layout layer; documented |
| RES-006 | — | NaN / non-finite float sizes | Attack focus listed NaN | `DesktopSize` axes are `u32`; `HostBounds` `i32` | **Rejected** — not representable; documented on `DesktopSize` |
| RES-007 | — | Drop calling `ApplyDesktopSize` | No sink stored on debouncer | API shape | **Rejected** — structurally impossible; pin cancel-not-flush (`last_emitted` must stay unset) |
| RES-008 | — | Oversized axis clamp to `MAX_DESKTOP_AXIS` | Configure validates ≤16384 | Debounce is pure coalesce | **Rejected** — session/configure concern; no Connect here |

## Fixes applied

- `rdp/resolution.rs` — `flush` always clears `due_at`; `due_at()` accessor; Drop/cancel docs; NaN/integer note; attack-focus regressions
- `docs/migration/05-rdp-spike.md` — debounce semantics table (modules table intact)
- `docs/migration/README.md` — ledger link

## Gate record

### Adversarial loop

| Cycle | Strategy | Accepted findings | Result |
|---|---|---|---|
| Adv-0 | Contract → boundary → state → concurrency → security → integration → perf → tests | RES-001…003 | Fixed; counter reset |
| Adv-1 | Same lanes on fixed tree; docs table integrity | RES-004 | Fixed; counter reset |
| Adv-2a | Contract→…→tests (post table fix) | None | Clean (1/2) |
| Adv-2b | Reverse: tests-as-oracles → Drop/`last_emitted` → C# timer stop → integer NaN N/A → no Connect | None | Clean (2/2) |

### Iterative-review-simplify (after adversarial clean)

| Cycle | Reuse | Efficiency | Quality/Bugs | Accepted | Result |
|---|---|---|---|---|---|
| Sim-fix | — | — | `due_at` among getters; `assert_eq!` for `last_emitted` | **Fixed** | Reset |
| Sim-1…3 | Shared `size()` / `from_*` helpers; reject merging cancel tests | No hot-path I/O; reject micro on instant→flush | Drop cancel-not-flush intact; RES-005…008 hold | None | Clean (3/3) |

### Adversarial re-loop (required after simplify edits)

| Cycle | Strategy | Accepted | Result |
|---|---|---|---|
| Adv-R1 | Delta: `due_at` getter move + prior flush/Drop invariants | None | Clean (1/2) |
| Adv-R2 | Reverse: degenerate skip, flush↔poll, instant/default 250, no CredSSP touch | None | Clean (2/2) |

Post re-loop simplify: three consecutive clean cycles (reuse / efficiency / quality) with no further accepted findings.

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-surface-win --features rdp
```

Result: **pass** — resolution unit tests (18) + full crate with `--features rdp`.

## Residual

- Live wiring of `ApplyDesktopSize` → `UpdateSessionDisplaySettings` remains deferred (`05-rdp-spike.md`).
- Layout→debouncer→Fake glue (`RdpResolutionLayoutGlue` / `FakeRdpResizeSurface`) covers the caller min-dim / coalesce path without OCX.
- Layout min-dimension (`IsDegenerate(8)`) stays outside the pure debouncer (enforced in the glue).
