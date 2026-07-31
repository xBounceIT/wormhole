# Adversarial ledger — BitwardenSession stub

**Scope:**
- `rust/crates/wormhole-secrets-win/src/bitwarden_session.rs` — `BitwardenSession`,
  `StubBitwardenSession`, `FakeBitwardenSession`, `BitwardenSessionKey`, free helpers
- Docs: `docs/migration/04-secrets.md`, `docs/migration/15-cutover.md`, this ledger + `README.md`
- Light touch: `wormhole-app` `services.rs` secrets feature type-check of `StubBitwardenSession`

**Out of scope:** C# `BitwardenCliVaultClient` / `BitwardenProcessRunner`; real `bw` spawn;
Bitwarden browser WebView2 profiles (`wormhole-http::bitwarden` / path helpers — separate surface);
WinRT Hello (see [adversarial-ledger-hello-cutover.md](adversarial-ledger-hello-cutover.md)).

**Authority:** full adversarial-review-fix (edit in scope)  
**Attack focus:** session key never in Debug/Display/logs; stub always locked / fail-closed;
Fake never spawns `bw` / never retains master password; empty password fail-closed (clears held key);
`BitwardenSessionKey::is_empty` whitespace-aware (C# `HasSessionKey`); docs: CLI unlock not
production-wired, browser path separate; tests assert via `expose()`, never
`format!("{:?}", key)` as secret oracle.  
**Impl ref:** `e2ab86b9-55bb-4f2c-a5b7-9eedc0e0c886`  
**Baseline:** `cargo test -p wormhole-secrets-win` — 98 green before this review  
**Final:** 99 green (+ whitespace `is_empty` + empty-pw clears-held-key coverage)

---

## Gate summary

| Gate | Result |
|---|---|
| Adversarial clean passes | **2** consecutive (post-fix) + **2** consecutive (post-simplify re-run) |
| Iterative-review-simplify clean passes | **3** consecutive (after simplify cycle-1 fix) |
| `cargo test -p wormhole-secrets-win` | **pass** (99) |

---

## Accepted findings (this review)

### BS-06 — Docs example asserted key after empty-password unlock (`P2`) — **fixed**

- **Where:** `docs/migration/04-secrets.md` Fake example
- **Invariant:** Empty / whitespace master password fails closed **and clears** any held key
- **Evidence:** Example did `unlock("")` then `session_key().unwrap().expose()` — would panic /
  contradict Fake behavior (`state.key = None` on blank password)
- **Impact:** Docs teach the wrong fail-closed contract
- **Fix:** Assert `expose()` while unlocked, then blank unlock, then `session_key().is_none()`
- **Regression:** `fake_empty_master_password_fails_closed` now unlocks then blank-clears held key

### BS-07 — `BitwardenSessionKey::is_empty` ignored whitespace (`P2`) — **fixed**

- **Where:** `BitwardenSessionKey::is_empty`
- **Invariant:** Parity with C# `HasSessionKey` / `IsNullOrWhiteSpace` — whitespace is not a
  usable `BW_SESSION`
- **Evidence:** `BitwardenSessionKey::new("   ").is_empty()` was `false` while Fake /
  `non_empty_session_key` reject whitespace
- **Impact:** Callers using `!key.is_empty()` could treat blank keys as valid
- **Fix:** `is_empty` uses `trim().is_empty()`; helper / unlock filter reuse `is_empty()`
- **Regression:** `session_key_is_empty_treats_whitespace_as_blank`

### Prior closed findings (still held)

| ID | Summary | Status |
|---|---|---|
| BS-01 | Fake multi-mutex lock-order deadlock → single `Mutex<FakeState>` | held |
| BS-02 | Empty session key could unlock → `non_empty_session_key` | held |
| BS-03 | Silent-unlock / env-shaped input under-pinned | held |
| BS-04 | Debug used as secret oracle under-pinned | held |
| BS-05 | Docs: CLI vs browser / not production-wired | held |

---

## Rejected candidates

| ID | Severity | Reason |
|---|---|---|
| REJ-01 | — | Wire real `bw` process — out of scope; stub intentionally fail-closed |
| REJ-02 | — | Custom Debug on `BitwardenUnlockResult` omitting message — Hello parity keeps UI-safe message in Debug |
| REJ-03 | — | `set_scripted_key` auto-toggling `allow_unlock` — independent knobs match Hello fake; documented |
| REJ-04 | — | Merge overlapping stub fail-closed tests — clarity preferred |
| REJ-05 | — | Session-key length in Debug/Display — intentional redaction pattern (parity with `AppAuthUnlock`) |
| REJ-06 | — | Mutate process env in tests to prove ignore — `set_var` unsafe; no `std::env` in module + password-shaped coverage |
| REJ-07 | — | C# / browser HTTP Bitwarden mutation — explicitly out of scope |
| REJ-08 | — | `BitwardenSessionKey::new` reject whitespace at construction — `is_empty` + Fake filter suffice; `new` stays thin wrapper |
| REJ-09 | — | `status()` check `!key.is_empty()` — blank held key unreachable via Fake public API |

---

## Adversarial cycles

| Pass | Strategy | Accepted | Result |
|---|---|---|---|
| Adv-1 | Contract → security → docs example sequencing | BS-06 | Fixed; reset |
| Adv-2 | Tests-as-oracles → C# HasSessionKey parity → boundary | BS-07 | Fixed; reset |
| Adv-3 | Integration (app touch) → no process/env → unicode | None | Clean (1/2) |
| Adv-4 | Attack checklist: Debug/stub/Fake/docs/expose | None | Clean (2/2) |
| Adv-5 | Post-simplify delta: `state_guard` / `fail_closed` | None | Clean (1/2 re-run) |
| Adv-6 | Concurrency + fail-closed path equivalence on delta | None | Clean (2/2 re-run) |

---

## Simplify passes (iterative-review-simplify)

| Cycle | Reuse | Efficiency | Quality | Disposition |
|---|---|---|---|---|
| 1 | Hello-style `state_guard`; duplicated fail-closed returns | — | Centralize mutex access + local `fail_closed`; fix `with_session_key` doc | **Fixed** → reset |
| 2 | Helper reused; unlock keeps empty re-check | No hot-path I/O | Fail-closed invariants intact | Clean (1/3) |
| 3 | No missed local helpers | Concurrent test adequate | Overlapping stub tests kept | Clean (2/3) |
| 4 | Same | Same | Diff hygiene / ledger | Clean (3/3) |

Simplify cycle 1 changed code → Adv-5/Adv-6 re-run completed clean; no further simplify edits.

---

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-secrets-win
```

**Result:** 99 passed; 0 failed. No live `bw` CLI / `HardwarePass`.
