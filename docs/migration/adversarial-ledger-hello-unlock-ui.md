# Adversarial ledger — Hello unlock UI glue (`wormhole-app`)

**Scope:**
- `rust/crates/wormhole-app/src/hello_unlock.rs` (+ `secrets` feature re-exports in `lib.rs` / `Cargo.toml`)
- Docs already covering the spike: `04-secrets.md`, `15-cutover.md`, `feature-matrix.md` (App lock row)

**Out of scope:** Live WinRT `UserConsentVerifier` / HardwarePass; GPUI lock-overlay chrome;
Bitwarden CLI session (`bitwarden_session` — do not churn); C# tree mutation; AppServices DI
wiring beyond the exported glue types.

**Authority:** full adversarial-review-fix (edit in scope)  
**Compared against:** C# `MainWindow.TryUnlockWithWindowsHelloAsync` + `WindowsHelloService` copy  
**Baseline:** `cargo test -p wormhole-app --lib hello_unlock --no-default-features --features secrets` — 8 green  
**Final:** **9** passed  

---

## Gate summary

| Gate | Result |
|---|---|
| Adversarial clean passes | **2** consecutive (post-fix; re-run after simplify) |
| Iterative-review-simplify clean passes | **3** consecutive |
| `cargo test -p wormhole-app --lib hello_unlock --no-default-features --features secrets` | **pass** (9) |

---

## Accepted findings

### HU-01 — Success forwarded freeform / spoofed verification messages (`P2`) — **fixed**

- **Where:** `hello_unlock.rs` `map_verification`
- **Invariant:** `status_text` is UI-safe fixed copy; Success / Cancelled must not echo Fake-scripted freeform (or cancel copy on a `verified: true` spoof)
- **Evidence:** Prior Success path used `verification.message` verbatim. `verified: true` + `HELLO_CANCELED_MESSAGE` unlocked with status `"Windows Hello was canceled."`; freeform `"Unlocked with hunter2-biometric"` would appear in `Display` / InfoBar
- **Impact:** Hosts showing `status_text` on unlock could flash cancel/secret-ish copy while actually unlocking
- **Fix:** Success / Cancelled always take `status_text_for(…)` constants; Unavailable still forwards probe/rejection reasons
- **Regression:** spoof + freeform asserts in `glue_maps_non_cancel_rejection_to_unavailable`; Fake constructor status pins; `glue_remote_fake_unavailable_skips_verification`

---

## Rejected candidates

| ID | Severity | Reason |
|---|---|---|
| REJ-01 | — | Wire live WinRT / HardwarePass — explicitly out of scope; Stub stays fail-closed |
| REJ-02 | — | Glue-level `_lockHelloInProgress` debounce — documented host responsibility (C# flag lives on MainWindow) |
| REJ-03 | — | Redact `HelloUnlockResult` `Display` — status is intentional UI copy; `Debug` already length-only |
| REJ-04 | — | Move Verified/Canceled constants into `wormhole-secrets-win` — WinRT producer not landed; avoid secrets churn |
| REJ-05 | — | Wire `HelloUnlockGlue` into `AppServices` — glue is exported for hosts; not required by this spike |
| REJ-06 | — | Classify Cancel via structured enum instead of exact C# cancel string — parity with service copy until WinRT |
| REJ-07 | — | `FakeHelloUnlockUi` Unavailable always `WINRT_HELLO_GAP` (not remote copy) — intentional simplified Fake |
| REJ-08 | — | Bitwarden session / `bw unlock` — out of scope; do not churn |

---

## Adversarial cycles

| Pass | Strategy | Accepted | Result |
|---|---|---|---|
| Adv-1 | Contract → security → Fake/Stub fail-closed → test resistance | HU-01 (+ remote / status pins) | Fixed; reset |
| Adv-2 | Boundary cancel drift → concurrency docs → integration | None (post-fix) | Clean (1/2) |
| Adv-3 | Tests-as-oracles → reverse security → Fake vs glue | None | Clean (2/2) |
| Post-simplify Adv | `status_text_for` reuse delta | None | Clean (2/2) |

---

## Simplify passes (iterative-review-simplify)

| Cycle | Reuse | Efficiency | Quality | Disposition |
|---|---|---|---|---|
| 1 | Success/Cancel `status_text` → `status_text_for` | — | — | **Fixed** → reset (+ adv re-run) |
| 2 | Shared helper stable; Fake prompt still uses Hello constants | No hot-path I/O | Cancel exact-match keeps `HELLO_CANCELED_MESSAGE` (clearer than helper-for-classify) | Clean (1/3) |
| 3 | No missed local helpers | Same | Fail-closed / Debug / one-shot Fake intact | Clean (2/3) |
| 4 | Same | Same | Diff hygiene / ledger | Clean (3/3) |

Simplify cycle 1 changed code → post-simplify adversarial re-run completed clean; Sim-2…4 clean with no further edits.

---

## Attack lane outcomes (summary)

| Lane | Outcome |
|---|---|
| Stub fail-closed (no silent unlock) | `HelloUnlockGlue::with_stub()` → Unavailable (`WINRT_HELLO_GAP` or remote) |
| Fake Success / Cancel / Unavailable | `FakeHelloUnlockUi` scripts + exhausted → Unavailable |
| Debug never retains prompts | Glue / Fake / Result `Debug` omit caller prompts + status body |
| Cancel vs other rejection | Exact `"Windows Hello was canceled."` only; drift → Unavailable |
| Probe failure skips verification | Availability `available: false` → no `request_verification` |
| No live WinRT / HardwarePass | Documented; Stub / Fake only |

---

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-app --lib hello_unlock --no-default-features --features secrets
```

Expected: **9** passed.
