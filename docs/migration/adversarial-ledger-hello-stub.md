# Adversarial ledger — Hello AvailabilityProbe / HelloPrompt stubs

**Scope:**
- `rust/crates/wormhole-secrets-win/src/hello.rs` (+ re-exports in `lib.rs`)
- Docs: `04-secrets.md` / `15-cutover.md` Hello / WinRT notes

**Out of scope:** Full WinRT `UserConsentVerifier` UI; C# tree mutation; Bitwarden CLI session (separate surface).

**Authority:** full adversarial-review-fix (edit in scope)  
**Compared against:** C# `WindowsHelloService` + `RemoteDesktopSessionDetector` (remote gate + fail-closed until WinRT)  
**Baseline:** `cargo test -p wormhole-secrets-win` green before review  
**Final:** 56 passed (14 Hello-focused)

---

## Gate summary

| Gate | Result |
|---|---|
| Adversarial clean passes | **2** consecutive (post-fix; re-run after each simplify batch) |
| Iterative-review-simplify clean passes | **3** consecutive |
| `cargo test -p wormhole-secrets-win` | **pass** (56) |

---

## Accepted findings

### HS-01 — `FakeHelloPrompt` Debug dumped freeform outcome messages (`P2`) — **fixed**

- **Where:** `hello.rs` `FakeHelloPrompt` `Debug`
- **Invariant:** Fake never retains/logs caller prompts or biometric secrets; harness `Debug` must stay clean
- **Evidence:** Prior `Debug` cloned full `HelloAvailability` / `HelloVerification` (including scripted `message` strings). Mis-set outcomes or accidental secrets would appear in panic / log formatting (same class as OTP / `AppAuthUnlock` Debug leaks)
- **Impact:** Test harness / logging could echo freeform strings that are not UI-safe
- **Fix:** Custom `Debug` exposes only `availability_available` / `verification_verified` + call counts; sequential mutex snapshots (never hold both locks)
- **Regression:** `fake_hello_prompt_scripted_without_ui`, `fake_set_outcomes_updates_without_retaining_prompt`, `fake_winrt_gap_and_remote_match_production_copy`

### HS-02 — Remote-metric precedence / stub edges under-pinned (`P3`) — **fixed**

- **Where:** `hello.rs` tests
- **Invariant:** `SM_REMOTESESSION` wins over local-looking `SESSIONNAME` (C# detector order); Stub never claims success for any HWND/prompt; Fake `Default` is fail-closed WinRT gap
- **Evidence:** Metric-only case covered; Console + metric=1 and empty-prompt Stub paths lacked explicit pins
- **Fix:** Extended `remote_metric_marks_session_remote` (`0x1000` + Console override); Stub empty-prompt / `isize::MAX`; `fake_default_is_fail_closed_winrt_gap`; strengthened Display contract test
- **Regression:** those tests

---

## Rejected candidates

| ID | Severity | Reason |
|---|---|---|
| REJ-01 | — | Wire WinRT `UserConsentVerifier` — documented gap; stubs must stay fail-closed |
| REJ-02 | — | `cfg(test)`-gate `FakeHelloPrompt` — other crates need injectable fakes; rustdoc marks tests-only |
| REJ-03 | — | Seal `HelloPrompt` / ban `verified: true` on trait — Fake must script success for unlock-flow tests |
| REJ-04 | — | Redact `HelloAvailability`/`HelloVerification` `Display`/`Debug` message fields — UI copy is intentional; producers own secret-free contract |
| REJ-05 | — | Merge overlapping Stub echo/success tests — clarity preferred |
| REJ-06 | — | `SESSIONNAME` Unicode / BOM edge speculation — parity is ASCII `RDP-` prefix with C# `OrdinalIgnoreCase` |

---

## Adversarial cycles

| Pass | Strategy | Accepted | Result |
|---|---|---|---|
| Adv-1 | Contract → security → Fake Debug / Stub fail-closed | HS-01 (+ test strengthen) | Fixed; reset |
| Adv-2 | Integration / remote-gate parity / test resistance | HS-02 | Fixed; reset |
| Adv-3 | Concurrency → docs WinRT gap → reverse security | None | Clean (1/2) |
| Adv-4 | Tests-as-oracles → public API → cutover consistency | None | Clean (2/2) |
| Post-simplify Adv | Constructor reuse / mutex guards / Debug lock order | None | Clean (2/2) |

---

## Simplify passes (iterative-review-simplify)

| Cycle | Reuse | Efficiency | Quality | Disposition |
|---|---|---|---|---|
| 1 | `winrt_gap` / `remote_session` → `with_outcomes` | — | — | **Fixed** → reset (+ adv re-run) |
| 2 | `availability_guard` / `verification_guard` | — | — | **Fixed** → reset (+ adv re-run) |
| 3 | — | — | Debug held both mutexes via temporaries | **Fixed** sequential snapshots → reset (+ adv re-run) |
| 4 | Guards + constructors stable | No hot-path I/O | Fail-closed / Debug contracts intact | Clean (1/3) |
| 5 | No missed local helpers | Same | Docs WinRT / Fake Debug notes aligned | Clean (2/3) |
| 6 | Same | Same | Diff hygiene / ledger | Clean (3/3) |

---

## Attack lane outcomes (summary)

| Lane | Outcome |
|---|---|
| Stub fail-closed (no silent unlock) | `StubHelloPrompt` / free helpers always `available`/`verified` = false; remote message or `WINRT_HELLO_GAP` |
| Fake never retains/logs prompts; Debug clean | Prompt args discarded; `Debug` = bools + counts only |
| Docs: WinRT `UserConsentVerifier` not wired | `04-secrets.md` / `15-cutover.md` / `WINRT_HELLO_GAP` explicit |
| Remote gate / `WINRT_HELLO_GAP` vs hello-cutover | Same remote message + gap string; remote gate ≠ local Hello success |

---

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-secrets-win
```

Expected: **56** passed.
