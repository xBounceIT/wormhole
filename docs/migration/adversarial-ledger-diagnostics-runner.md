# Adversarial ledger — diagnostics SoakRunner glue

**Scope:** `rust/crates/wormhole-diagnostics/src/runner.rs` (+ crate re-exports), soak helper interaction in `soak.rs` as consumed by the runner, `docs/migration/19-diagnostics-soak.md` SoakRunner / FakeClock notes  
**Out of scope:** live multi-hour soak, HardwarePass / cutover, WireGuard establish expansion, diagnostics report/sidecars (see [adversarial-ledger-diagnostics.md](./adversarial-ledger-diagnostics.md))  
**Authority:** full adversarial-review-fix (edit in scope)  
**Baseline:** `cargo test -p wormhole-diagnostics` — 18 passed / 1 ignored before runner attack pass  
**Final:** **26** passed / 1 ignored  

---

## Gate summary

| Gate | Result |
|---|---|
| Adversarial clean passes | **2** consecutive (post-fix + post-simplify re-run) |
| Iterative-review-simplify clean passes | **3** consecutive (after last fix batch) |
| `cargo test -p wormhole-diagnostics` | **pass** (26 + 1 ignored) |
| Live 8h soak / HardwarePass | **not claimed** |

---

## Accepted findings

### RUN-01 — `FakeClock::set` could rewind and shrink `elapsed` (`P2`) — **fixed**

- **Where:** `runner.rs` `FakeClock::set`
- **Invariant:** Attack focus — clock freeze/jump / status drift; `SoakClock` is monotonic
- **Evidence:** `set` to an earlier `Duration` while `Running` made `status().elapsed` shrink via `saturating_sub`
- **Fix:** `set` only moves forward (`now.max(at)`); docs note never-rewinds
- **Regression:** `fake_clock_set_never_rewinds`

### RUN-02 — Attack-vector lifecycle contracts unpinned (`P2`) — **fixed**

- **Where:** `runner.rs` tests
- **Invariant:** Attack focus — double start, cancel idempotency (state-stable), poll after cancel, status drift after cancel+clock advance, clock freeze, restart after cancel, zero planned
- **Evidence:** Only happy-path + one restart-after-completed test; cancel/poll/clock edge paths unasserted
- **Fix:** Focused regressions (no API change for cancel `Err` on non-Running — state must remain identical)
- **Regression:** `double_start_while_running_is_rejected`, `cancel_when_idle_and_double_cancel_leave_state_stable`, `poll_after_cancel_is_noop_and_elapsed_freezes`, `clock_freeze_keeps_running_until_advance_and_poll`, `restart_after_cancel_resets_counters`, `zero_planned_completes_on_first_poll`, `cancel_after_completed_does_not_rewrite_phase`

### DOC-R01 — SoakRunner FakeClock monotonicity undocumented (`P3`) — **fixed**

- **Where:** `docs/migration/19-diagnostics-soak.md`
- **Fix:** FakeClock row notes `set` never rewinds; ledger link for runner glue

---

## Rejected candidates

| ID | Severity | Reason |
|---|---|---|
| REJ-01 | — | Make `cancel` return `Ok` when already `Cancelled` — current contract returns `Err(NotRunning)`; state is already mutation-idempotent; changing Ok semantics would break the pinned API without a doc requirement |
| REJ-02 | — | Scrub `password=` in `SoakReport::format` like env diagnostics — report fields are numeric / enum only; no string injection surface |
| REJ-03 | — | Live 8h soak / RSS / HWND hardware gates — explicit non-goals |
| REJ-04 | — | Expand WireGuard establish / touch `wireguard/mod.rs` — compile-healthy; out of scope |
| REJ-05 | — | `report.elapsed_secs` truncates sub-second vs `status.elapsed` — field is seconds by design; SOAK path uses whole hours |
| REJ-06 | — | Share redaction helpers with `report.rs` — over-abstraction for numeric soak summary |

---

## Simplify passes (iterative-review-simplify)

| Cycle | Reuse | Efficiency | Quality | Disposition |
|---|---|---|---|---|
| 1 | Drop dead `stress_batch > 0` branch (always ≥ 1) | `FakeClock::set` → `max` | — | **Fixed** (reset adv + simplify counters) |
| 2 | No findings | No findings | No findings | **clean 1** |
| 3 | No findings | No findings | No findings | **clean 2** |
| 4 | No findings | No findings | No findings | **clean 3** |

---

## Adversarial cycles

| Pass | Strategy | Result |
|---|---|---|
| Adv-1 | Contract → boundaries → state → concurrency → security → tests | RUN-01, RUN-02, DOC-R01 accepted → fixed; counter reset |
| Adv-2 | Security → concurrency → contract → boundaries (independent order) | **clean 1** |
| Adv-3 | Operability → integration → state → security | **clean 2** |
| Adv-4 (post-simplify) | Security + state on simplify delta (`set`/`poll`) | **clean 1** |
| Adv-5 (post-simplify) | Contract + test-resistance re-read | **clean 2** |

---

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-diagnostics
```

- `cargo test -p wormhole-diagnostics` → **26 passed, 1 ignored**
- Unrelated: normalized bare-CR in `wormhole-tunnels` Fortinet `mod.rs` doc comment so diagnostics (depends on tunnels) could compile during review — not part of SoakRunner scope

---

## Closure

- No accepted non-blocked findings remain
- **2** consecutive adversarial clean cycles after last fix batch
- **3** consecutive iterative-review-simplify clean cycles
- Unrelated user changes outside scope left intact (WireGuard establish not expanded)
