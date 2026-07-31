# Adversarial ledger — Transient session credential store

**Scope:**
- `rust/crates/wormhole-secrets-win/src/transient_session.rs` —
  `TransientSessionCredentialStore`, `MemoryTransientSessionCredentialStore`,
  `FakeTransientSessionCredentialStore`
- `SecretsError::EmptyPassword` Display/Debug in `lib.rs`
- Docs: `docs/migration/04-secrets.md`, `feature-matrix.md`, `interop-inventory.md`,
  this ledger + `README.md`

**Out of scope:** Shell / session / Quick Connect DI wiring into `wormhole-app` /
`wormhole-ui` (matrix: Pending); CredMgr / DPAPI persistence; HardwarePass;
zeroize-on-drop beyond C# `ConcurrentDictionary` parity.

**Authority:** full adversarial-review-fix (edit in scope)  
**Compared against:** C# `ITransientSessionCredentialStore` /
`TransientSessionCredentialStore` (`Services/ITransientSessionCredentialStore.cs`);
empty → `ThrowIfNullOrEmpty`; whitespace accepted; missing remove no-op; never
SQLite / CredMgr / DPAPI; Debug never embeds password material  
**Baseline:** `cargo test -p wormhole-secrets-win --lib transient_session` — 10 green  
**Final:** `cargo test -p wormhole-secrets-win --lib` — **112** passed (13 transient)

---

## Gate summary

| Gate | Result |
|---|---|
| Adversarial clean passes | **2** consecutive (post-fix) + **2** consecutive (post-simplify re-run) |
| Iterative-review-simplify clean passes | **3** consecutive (after cycle-1 Debug DRY) |
| `cargo test -p wormhole-secrets-win --lib` | **pass** (112) |
| `cargo test -p wormhole-secrets-win --lib transient_session` | **pass** (13) |

---

## Accepted findings

### TC-01 — Memory empty-password fail-closed under-pinned (`P2`) — **fixed**

- **Where:** `MemoryTransientSessionCredentialStore::store`
- **Invariant:** Empty `""` → `SecretsError::EmptyPassword`; existing entry under the
  same key must remain (C# `ThrowIfNullOrEmpty` before map write)
- **Evidence:** Only `FakeTransientSessionCredentialStore` had
  `empty_password_fails_closed_and_leaves_map_unchanged`; production Memory path
  shared the helper but had no direct pin
- **Impact:** Memory/Fake contract drift on reject-before-insert could ship unnoticed
- **Fix:** `memory_empty_password_fails_closed_and_leaves_map_unchanged`
- **Regression:** that test

### TC-02 — Production concurrent + interleaved clear under-pinned (`P2`) — **fixed**

- **Where:** `MemoryTransientSessionCredentialStore` (Mutex `HashMap` + Debug)
- **Invariant:** Concurrent store/read/remove/clear must not panic or poison; Debug
  under contention never echoes passwords; map remains usable after settle
- **Evidence:** Only Fake had `concurrent_store_read_remove_is_safe`; production type
  (used for DI) lacked Mutex/Debug/clear stress
- **Impact:** Poison-recovery or Debug regressions on the live store could pass
  single-threaded Memory tests
- **Fix:** `memory_concurrent_store_read_remove_clear_is_safe` (no exact per-key
  asserts while clear races; post-settle store/read + Debug redaction)
- **Regression:** that test

### TC-03 — Unicode / embedded NUL round-trip under-pinned (`P3`) — **fixed**

- **Where:** Memory + Fake `store` / `read` / `Debug`
- **Invariant:** UTF-8 (accents / astral) and embedded `\0` survive; Debug never
  echoes those code units
- **Evidence:** CredMgr path pins NUL/Unicode; transient memory store did not
- **Fix:** `unicode_and_embedded_nul_roundtrip_never_echoed_in_debug`
- **Regression:** that test

### TC-04 — Feature matrix still said “live store Pending” (`P3`) — **fixed**

- **Where:** `docs/migration/feature-matrix.md` Creds / transient row
- **Evidence:** Rust `transient_session` stub already shipped; matrix claimed only QC
  state + Pending live store
- **Fix:** Lab row points at `wormhole-secrets-win::transient_session`; shell/session
  DI wiring remains Pending

### TC-05 — Interop inventory omitted Rust ownership (`P3`) — **fixed**

- **Where:** `docs/migration/interop-inventory.md` §5.3 transient row
- **Fix:** Note `wormhole-secrets-win::transient_session` (`Memory`/`Fake`; never
  SQLite/CredMgr/DPAPI)

---

## Rejected candidates

| ID | Severity | Reason |
|---|---|---|
| REJ-01 | — | Zeroize-on-remove / Drop — C# `ConcurrentDictionary` does not; out of stub scope |
| REJ-02 | — | CredMgr 2560 UTF-16 ceiling on transient — memory-only by design; no vault write |
| REJ-03 | — | Merge Memory + Fake into one storage struct — rejected; matches `FakePasswordStore` split |
| REJ-04 | — | `store` take `String` by value — `&str` + defensive `to_owned` matches CredMgr Fake |
| REJ-05 | — | Treat whitespace as empty — would break C# `ThrowIfNullOrEmpty` parity |
| REJ-06 | — | Wire shell/QC DI in `wormhole-app` — explicitly Pending / out of scope |
| REJ-07 | — | Debug “contains password” oracle when password equals field names (`entry_count`) — tests use distinctive secrets |
| REJ-08 | — | Session-id vs node-id collision — same shared-key map as C#; documented |

---

## Adversarial cycles

| Pass | Strategy | Accepted | Result |
|---|---|---|---|
| Adv-1 | Contract → boundary → concurrency → docs | TC-01..04 | Fixed; reset |
| Adv-2 | Security → integration → C# call-site parity | TC-05 | Fixed; reset |
| Adv-3 | Test resistance → Unicode/NUL → trait DI | None | Clean (1/2) |
| Adv-4 | Attack checklist: empty/whitespace/Debug/clear/never-persist | None | Clean (2/2) |
| Adv-5 | Post-simplify delta: `entry_utf8_byte_lengths` helper | None | Clean (1/2 re-run) |
| Adv-6 | Fail-closed path equivalence Memory≡Fake + concurrent settle | None | Clean (2/2 re-run) |

---

## Simplify passes (iterative-review-simplify)

| Cycle | Reuse | Efficiency | Quality | Disposition |
|---|---|---|---|---|
| 1 | Duplicated Debug length collection | — | Shared `entry_utf8_byte_lengths` | **Fixed** → reset |
| 2 | Helper reused; Memory/Fake map merge rejected | No hot-path I/O | Fail-closed + concurrent pins intact | Clean (1/3) |
| 3 | `ensure_non_empty_password` already shared | Clone-on-read matches C# string return | Overlapping empty tests kept (Memory vs Fake) | Clean (2/3) |
| 4 | Same | Same | Diff hygiene / ledger / README | Clean (3/3) |

Simplify cycle 1 changed code → Adv-5/Adv-6 re-run completed clean; no further simplify edits.

---

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-secrets-win --lib transient_session
cargo test -p wormhole-secrets-win --lib
```

**Result:** 13 transient + 112 crate lib tests passed; 0 failed. No HardwarePass / no git commit.
