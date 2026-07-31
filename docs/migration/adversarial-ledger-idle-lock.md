# Adversarial ledger — App idle-lock timeout glue

**Scope:**
- `rust/crates/wormhole-secrets-win/src/idle_lock.rs` (+ re-exports in `lib.rs`)
- Light docs: `04-secrets.md`, `15-cutover.md`, `feature-matrix.md`,
  `interop-inventory.md`, README ledger index, this ledger

**Out of scope:** `app_auth_service` / `hello_unlock` rewrites; live
`GetLastInputInfo` / suspend-gap (`SuspendedTimerGap`); GPUI lock overlay;
WinRT Hello; C# MainWindow timer wiring; Bitwarden session.

**Authority:** full adversarial-review-fix (edit in scope)  
**Impl:** parent agent (no child agents)  
**Compared against:** C# `AppInactivityLockEvaluator` + user brief (last-activity /
Fake clock / fail-closed zero-negative)  
**Baseline:** `cargo test -p wormhole-secrets-win --lib idle_lock` — 13 green
(pre-review)  
**Final:** **16** `idle_lock` tests green  

Context7 MCP unavailable in this environment.

---

## Gate summary

| Gate | Result |
|---|---|
| Adversarial clean passes | **2** consecutive (post-fix) + **2** post-simplify re-adv |
| Iterative-review-simplify clean passes | **3** consecutive |
| `cargo test -p wormhole-secrets-win --lib idle_lock` | **pass** (16) |

---

## Accepted findings

### IL-01 — Flaky `system_clock_advances` sleep (`P3`) — **fixed**

- **Where:** `idle_lock.rs` tests
- **Invariant:** Unit tests must not depend on wall sleep
- **Fix:** `system_clock_is_monotonic` (no sleep) + host usability assert
- **Regression:** that test

### IL-02 — Docs / inventory under-indexed (`P2`) — **fixed**

- **Where:** `04-secrets.md`, `15-cutover.md`, `feature-matrix.md`,
  `interop-inventory.md`, `README.md`
- **Fix:** Brief idle-lock rows + ledger link

### IL-03 — Stale construction epoch under-pinned (`P2`) — **fixed**

- **Where:** `AppIdleLockGlue::new` rustdoc + tests
- **Invariant:** Seeding with `IdleInstant::ZERO` while `now` is advanced looks
  fully idle (hosts must seed with `clock.now()` / `with_fake`)
- **Fix:** rustdoc + `stale_epoch_construction_locks_when_now_advanced`

### IL-04 — Rewound `now` / FakeClock under-pinned (`P2`) — **fixed** (pre-review + pins)

- **Where:** `note_activity`, `FakeIdleClock::set`, `saturating_duration_since`
- **Invariant:** Idle / clocks stay monotonic; hostile rewind does not shrink idle
  into a lock skip incorrectly for positive timeouts (saturates to zero idle)
- **Regression:** `note_activity_ignores_rewound_now`, `fake_clock_set_never_rewinds`,
  `now_before_last_activity_saturates_to_zero_idle`

### IL-05 — `i32::MAX` timeout wrap risk under-pinned (`P3`) — **fixed**

- **Where:** `should_lock` duration build
- **Fix:** `saturating_mul` + `large_positive_timeout_does_not_lock_immediately`

---

## Rejected candidates

| ID | Severity | Reason |
|---|---|---|
| REJ-01 | — | Port C# `SuspendedTimerGap` / `GetLastInputInfo` — explicit thin-stub non-goal; host OS idle Unwired |
| REJ-02 | — | Match C# `minutes <= 0 → false` — user required **fail-closed** lock for zero/negative; `None` remains UI "Never" |
| REJ-03 | — | Rewrite `app_auth_service` / `hello_unlock` — forbidden by brief |
| REJ-04 | — | Own `AppLockState` eventing — host owns lock overlay; glue is policy-only |
| REJ-05 | — | Re-export from `wormhole-app` — secrets-win placement is enough |
| REJ-06 | — | Make `mark_unlocked` distinct state from `note_activity` — C# `MarkUnlocked` only resets idle samples; alias is correct |

---

## Adversarial cycles

| Pass | Strategy | Accepted | Result |
|---|---|---|---|
| Adv-1 | Contract → boundaries → clock mono → docs → tests | IL-01…IL-05 | Fixed; reset |
| Adv-2 | Security fail-closed → Disabled/Never → already-locked | None | Clean (1/2) |
| Adv-3 | Integration drift / C# parity deltas / Debug | None (REJ-01/02 noted) | Clean (2/2) |
| Post-simplify Adv | Delta on rustdoc / tests only | None | Clean (2/2) |

---

## Simplify passes (iterative-review-simplify)

| Cycle | Reuse | Efficiency | Quality | Disposition |
|---|---|---|---|---|
| 1 | `mark_unlocked` → `note_activity` | Atomic counters only on evaluate/`note` | Stale-epoch rustdoc | Clean notes only |
| 2 | Shared `minutes` test helper | No wall sleep | Fail-closed vs Never distinction clear | Clean (1/3) |
| 3 | Crate prelude smoke via `crate::` | — | Ledger / inventory | Clean (2/3) |
| 4 | Same | Same | No further edits | Clean (3/3) |

---

## Attack lane outcomes (summary)

| Lane | Outcome |
|---|---|
| Contract | Disabled / Never / fail-closed zero-negative / activity reset pinned |
| Boundaries | `i32::MIN`/`MAX`, rewind now, exact timeout edge |
| State | already-locked suppresses re-fire; unlock resets window |
| Concurrency | Single-threaded host API (`&mut` note / `&self` evaluate); Fake `Rc<Cell>` |
| Security | No secrets held; Debug counts/durations only |
| Integration | Does not churn Hello / PIN verifier modules |
| Tests | 16 focused `idle_lock` tests |

---

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-secrets-win --lib idle_lock
```

**Result:** 16 passed.
