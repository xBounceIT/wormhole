# Adversarial ledger — App-auth PIN/password Fake verifier

**Scope:**
- `rust/crates/wormhole-secrets-win/src/app_auth_service.rs` (+ re-exports in `lib.rs`)
- Light docs: `04-secrets.md`, `15-cutover.md`, this ledger + `README.md`
- Related read-only: `app_auth.rs` DPAPI store helpers (stub unlock; not Hello UI)

**Out of scope:** Interactive Windows Hello / WinRT `UserConsentVerifier`;
`wormhole-app::hello_unlock` UI glue (do not churn); C# tree/settings mutation;
idle lock timer; Bitwarden session.

**Authority:** full adversarial-review-fix (edit in scope)  
**Compared against:** C# `AppAuthenticationService` + `IAppAuthenticationDataProtector`
(+ PassThroughProtector tests)  
**Attack focus:** wrong/missing/corrupt fail-closed; Fake never logs secrets;
PBKDF2 iteration DoS / i32 JSON bounds; ASCII PIN + UTF-16 password length;
slot independence; Debug redaction; Hello fallback slot only (no biometric claim).  
**Baseline:** `cargo test -p wormhole-secrets-win --lib app_auth` green (20) before review  
**Final:** 28 app_auth* tests green (23 `app_auth_service` + 5 `app_auth`)

---

## Gate summary

| Gate | Result |
|---|---|
| Adversarial clean passes | **2** consecutive (post-fix) + **2** consecutive (post-simplify re-run) |
| Iterative-review-simplify clean passes | **3** consecutive (after simplify cycle-1 reuse fix) |
| `cargo test -p wormhole-secrets-win --lib app_auth` | **pass** (28) |
| `cargo test -p wormhole-secrets-win --lib` | **pass** (135; one CredMgr unicode flake on a parallel run was pre-existing / out of scope and passed on rerun) |

---

## Accepted findings

### AA-01 — Unbounded stored `Iterations` → unlock DoS (`P1`) — **fixed**

- **Where:** `is_valid_verifier_shape` / `verify` / `with_protector`
- **Invariant:** Hostile or corrupt `app-auth.dpapi` must not force multi-hour PBKDF2 on verify
- **Evidence:** Shape previously required only `iterations > 0`. JSON with
  `"Iterations": 2147483647` + valid salt/hash lengths passed shape and would run
  PBKDF2 for ~2^31 rounds on unlock. Shipping C# always writes `DefaultPbkdf2Iterations`
  (600_000); injectable C# ctor can go higher but production does not.
- **Impact:** Local profile tampering / sync of a hostile blob hangs the unlock path
- **Fix:** `MAX_PBKDF2_ITERATIONS = DEFAULT_PBKDF2_ITERATIONS`; constructor panics outside
  `1..=MAX`; shape + verify reject higher counts as corrupted / false
- **Regression:** `hostile_verifier_shape_is_corrupted_and_rejects_verify`,
  `max_iterations_constant_matches_default`

### AA-02 — `u32`→`i32` cast for JSON `Iterations` could wrap (`P2`) — **fixed**

- **Where:** `create_verifier` (`iterations as i32`)
- **Invariant:** Written `Iterations` must stay positive and dual-host JSON-safe
- **Evidence:** Constructor previously allowed any `u32 > 0`. Values `> i32::MAX` wrap to
  negative on write → next read marks store corrupted
- **Impact:** Misconfigured injectable iterations corrupt the store after a “successful” set
- **Fix:** Constructor capped to `MAX_PBKDF2_ITERATIONS` (600_000 ≪ `i32::MAX`); write uses
  `as i32` under that invariant
- **Regression:** covered by constructor assert + `max_iterations_constant_matches_default`

### AA-03 — UTF-16 password length / ASCII PIN under-pinned (`P2`) — **fixed**

- **Where:** `validate_password` / `validate_pin` tests
- **Invariant:** Password length matches C# `string.Length` (UTF-16 code units); PIN is
  ASCII digits only (stricter than C# `char.IsDigit`, intentional for keypad UI)
- **Evidence:** Range tests used ASCII only; astral emoji length and Unicode Nd digits
  lacked regression pins
- **Fix:** `password_length_uses_utf16_code_units`, `pin_rejects_non_ascii_digits`
- **Regression:** those tests

### AA-04 — Hostile / protector-failure shapes under-pinned (`P2`) — **fixed**

- **Where:** `read_document` corruption paths
- **Invariant:** Bad salt length, protector `Unprotect` failure → corrupted + verify false;
  overwriting one slot preserves the other
- **Evidence:** Only generic `not-json` corruption tested; PassThrough unprotect-failure and
  sibling-slot overwrite lacked pins
- **Fix:** `wrong_salt_length_verifier_is_corrupted`,
  `protector_unprotect_failure_marks_corrupted`,
  `overwriting_pin_preserves_password_slot`, `clear_missing_store_is_ok`
- **Regression:** those tests

---

## Rejected candidates

| ID | Severity | Reason |
|---|---|---|
| REJ-01 | — | Wire WinRT Hello / change `hello_unlock` — explicitly out of scope |
| REJ-02 | — | Match C# `char.IsDigit` (Unicode Nd) for PIN — ASCII-only is intentional fail-closed |
| REJ-03 | — | Match C# fixed `path + ".tmp"` temp name — Guid sibling matches other DPAPI atomics; safer under concurrency |
| REJ-04 | — | Cap verify early on secret length (skip PBKDF2) — C# does not; would add timing oracle |
| REJ-05 | — | `cfg(test)`-gate Fake protector — other crates need injectable fakes; rustdoc marks tests-only |
| REJ-06 | — | Merge overlapping set/verify mode tests — clarity preferred |
| REJ-07 | — | Extract `atomic_replace_bytes` into `dpapi` for `write_document` — trait-based protect blocks reuse of `write_protected_file_atomic`; churn without clear win |
| REJ-08 | — | Zeroize `AppAuthenticationVerifierJson` on Drop — C# parity / stored material; not required for this spike |

---

## Adversarial cycles

| Pass | Strategy | Accepted | Result |
|---|---|---|---|
| Adv-1 | Contract → security (PBKDF2 DoS / i32) → boundary inputs | AA-01, AA-02, AA-03 | Fixed; reset |
| Adv-2 | Test resistance → protector failure → slot independence | AA-04 | Fixed; reset |
| Adv-3 | Concurrency → Fake Debug → reverse security on caps | None | Clean (1/2) |
| Adv-4 | Integration docs / public API / Hello-fallback non-claim | None | Clean (2/2) |
| Post-simplify Adv-5 | Delta: `verifier_shape_ok` shared helper | None | Clean (1/2 re-run) |
| Post-simplify Adv-6 | Fail-closed path equivalence + Fake/tests on delta | None | Clean (2/2 re-run) |

---

## Simplify passes (iterative-review-simplify)

| Cycle | Reuse | Efficiency | Quality | Disposition |
|---|---|---|---|---|
| 1 | Duplicated iteration/salt/hash checks in shape + verify | — | try_from after MAX cap redundant | **Fixed** → `verifier_shape_ok` + `as i32`; reset (+ adv re-run) |
| 2 | Shared helper stable; no missed local helpers | No hot-path I/O beyond C# parity | Temp-path comment corrected earlier; docs MAX note aligned | Clean (1/3) |
| 3 | Same | Same | ASCII PIN / UTF-16 docs + ledger links intact | Clean (2/3) |
| 4 | Same | Same | Diff hygiene; `hello_unlock` untouched | Clean (3/3) |

---

## Attack lane outcomes (summary)

| Lane | Outcome |
|---|---|
| Wrong / missing / corrupt verify | `Ok(false)`; status `is_corrupted` when applicable |
| Hostile oversized `Iterations` | Shape reject → corrupted; no PBKDF2 DoS |
| Fake protector | Pass-through; Debug = call counts only; never echoes blobs |
| PIN / password rules | ASCII digits 4–12; password 8–128 UTF-16 units |
| Modes | Disabled verify-true / not configured; Pin/Password slots; Hello = fallback slot only |
| Secrets in logs | `InvalidAppAuthSecret` fixed copy; Debug length/flags only |

---

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-secrets-win --lib app_auth
```

Expected: **28** passed (app_auth + app_auth_service).
