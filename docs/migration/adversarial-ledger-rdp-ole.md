# Adversarial ledger — RDP OLE in-place hosting + event sink

Scope: `rust/crates/wormhole-surface-win/src/rdp/` (`site`, `events`, `ocx`, `overlay`, `sentinel`, STA), `rust/crates/surface-lab/` gate06 + `rdp` feature, `docs/migration/05-rdp-spike.md`  
Out of scope: C# sources; CredSSP / gateway / resolution debounce (deferred)  
Constraints: never introduce `SetParent` / `WS_CHILD`; preserve `GWLP_HWNDPARENT` overlay + crash sentinel Mark/Clear  
Baseline before OLE review: `cargo check` + `cargo test -p wormhole-surface-win` green; `--features rdp` green (overlay/sentinel suite from prior RDP ledger)

## Findings

| ID | Sev | Location | Issue | Evidence | Disposition |
|---|---|---|---|---|---|
| OLE-001 | P1 | `rdp/events.rs` | Only Connected had a Clear hook; Disconnected / FatalError left Mark orphans | Docs + C# clear once session leaves danger window; Invoke ignored terminal paths for hooks | **Fixed** — `set_on_disconnected` / `set_on_fatal_error` + `set_on_sentinel_clear`; gate06 wires Clear on all three |
| OLE-002 | P1 | `rdp/ocx.rs` Drop / activate | Re-`activate_in_place` leaked prior site/Advise; drop order vs overlay HWND undocumented | Second DoVerb without revoke; site HWND stale if host destroyed first | **Fixed** — `revoke_site_keep_object` before re-activate; Drop = Unadvise → Close → `SetClientSite(None)`; docs + gate06/tests drop OCX before host |
| OLE-003 | P2 | `rdp/ocx.rs` `run_on_sta` | Panic in STA body skipped `OleUninitialize` | Manual Uninitialize after `f()` only on normal path | **Fixed** — `OleInitGuard` RAII |
| OLE-004 | P2 | `rdp/events.rs` Invoke | Hook ran under `RefCell` borrow; panic could escape COM | Reentrant state read panics; C# uses `Safe` | **Fixed** — take/call/restore + `catch_unwind`; reentrancy + panic tests |
| OLE-005 | P2 | tests | No unit coverage for sink Invoke / sentinel Clear trio without mstsc | Only overlay HWND tests under `rdp` | **Fixed** — events unit tests invoke DISPIDs without CoCreate; OCX STA smoke tolerates missing mstscax |
| OLE-006 | — | Explicit `InPlaceDeactivate` before Close | OLE `Close` deactivates in-place object | MSDN Close semantics | **Rejected** — Close is sufficient for spike |
| OLE-007 | — | Enforce drop order in type system | Host could still be dropped while OCX live | Would need owning wrapper / typestate | **Rejected** — documented + lab/tests pin order; owning host is later broker work |
| OLE-008 | — | `SetParent` / `WS_CHILD` | Grep + style asserts | Only comments / checks forbidding | **Rejected** — invariant held |
| OLE-009 | — | Password / ClearTextPassword on Connect stub | API is server+port only | Grep | **Rejected** — clean |
| OLE-010 | — | CredSSP / gateway / 250 ms debounce | Attack focus lists as deferred | `05-rdp-spike.md` | **Rejected** — deferred by design |

## Fixes applied

- `rdp/events.rs` — lifecycle hooks, sentinel Clear helper, reentrancy-safe Invoke, panic swallow, unit tests
- `rdp/ocx.rs` — `OleInitGuard`, revoke-before-reactivate, documented drop order, STA activate/drop tests
- `rdp/site.rs` — shared `ensure_min_rect` (also used by `ocx`)
- `rdp/host.rs` — drop-order docs
- `surface-lab` gate06 — `set_on_sentinel_clear`; OCX dropped before overlay HWND
- `docs/migration/05-rdp-spike.md` — Clear trio + OLE teardown notes

## Gate record

### Adversarial loop

| Cycle | Strategy | Accepted findings | Result |
|---|---|---|---|
| Adv-0 (initial) | Contract → boundary → state → concurrency/lifecycle → security → integration → perf → tests | OLE-001…005 | Fixed; counter reset |
| Adv-1 | Same lanes on fixed tree (hooks, drop order, OleInit, !Send, no SetParent) | None | Clean (1/2) |
| Adv-2 | Reverse: tests-as-oracles → secrets → Advise/Unadvise → C# Clear parity → STA DoVerb | None | Clean (2/2) |

### Iterative-review-simplify (after adversarial clean)

| Cycle | Reuse | Efficiency | Quality/Bugs | Accepted | Result |
|---|---|---|---|---|---|
| Sim-fix | Triplicated Invoke arms; duplicate min-rect clamp | — | Weak `!Send` “test” asserted nothing | **Fixed** `take_call_restore`, `ensure_min_rect`, removed weak test | Reset |
| Sim-1 | Shared helpers used by site+ocx+events | No hot-path I/O in sink | Hooks restored after panic; Mark/Clear intact | None | Clean (1/3) |
| Sim-2 | gate06 single Clear wiring | STA pump lab-only | No SetParent; OCX-before-host pinned | None | Clean (2/3) |
| Sim-3 | Feature `rdp` still gates COM modules | Default build stays light | Docs match Clear trio + OleInit guard | None | Clean (3/3) |

### Adversarial re-loop (required after simplify edits)

| Cycle | Strategy | Accepted | Result |
|---|---|---|---|
| Adv-R1 | Delta: `take_call_restore`, `ensure_min_rect`, revoke path | None | Clean (1/2) |
| Adv-R2 | Reverse: STA/`!Send`, sentinel Clear on FatalError/Disconnect, overlay styles | None | Clean (2/2) |

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo check
cargo test -p wormhole-surface-win
cargo test -p wormhole-surface-win --features rdp
cargo check -p wormhole-surface-win --features rdp
cargo check -p surface-lab --features rdp
```

Result: **pass** — default check green without `rdp`; 32 unit tests without `rdp` feature; 42 with `--features rdp` (events + STA/OLE smoke).

## Deferred (explicit)

Still out of this OLE spike (see `05-rdp-spike.md`):

- CredSSP / `EnableCredSspSupport` + full Configure
- RD Gateway (`TransportSettings2`)
- Resolution debounce (`UpdateSessionDisplaySettings`, 250 ms) + SmartSizing re-assert
- Full `IMsTscAxEvents` beyond Connected / Disconnected / FatalError
- Owner `WM_WINDOWPOSCHANGED` sync-move; broker layout ticks driving live `RdpOverlayHost`
- Focus target = AxHost child HWND (overlay stand-in today)
- Type-system enforcement of OCX-before-host drop order (documented only)
