# Adversarial ledger — CredMgr password CRUD glue

**Scope:**
- `rust/crates/wormhole-secrets-win/src/cred_mgr.rs` — `store_password` / `read_password` / `delete_password`, `PasswordStore` / `WinCredPasswordStore` / `FakePasswordStore`, `credential_target` / `Wormhole:<credId>` keys
- `SecretsError::PasswordTooLarge` Display/Debug (size only) in `lib.rs`
- Docs: `docs/migration/04-secrets.md` CredMgr API rows

**Out of scope:** DPAPI keys/tunnels (`key_tunnel` / path confinement); Hello / Bitwarden / HardwarePass / cutover; RDP `MAX_PASSWORD_CHARS`; deep re-litigation of the 2560 UTF-16 size oracle (closed in [adversarial-ledger-credmgr-size.md](adversarial-ledger-credmgr-size.md) — still exercised as a write-path gate here).

**Authority:** full adversarial-review-fix (edit in scope)  
**Compared against:** C# `CredentialService` CredMgr password CRUD; `Wormhole:<guid:D>`; missing delete → Ok(()); Debug never embeds password material  
**Baseline:** `cargo test -p wormhole-secrets-win` — 78 green before review  
**Final:** 89 passed

---

## Gate summary

| Gate | Result |
|---|---|
| Adversarial clean passes | **2** consecutive (independent attack order; post Adv-1 fixes) |
| Iterative-review-simplify clean passes | **3** consecutive (no implementation edits) |
| `cargo test -p wormhole-secrets-win` | **pass** (89) |

---

## Accepted findings

### CRUD-01 — `CredReadW` buffer not Drop-guarded (`P2`) — **fixed**

- **Where:** `cred_mgr.rs` `read_password_windows`
- **Invariant:** CredMgr buffers from `CredReadW` must be `CredFree`'d even if decoding panics / future edits insert fallible work between read and free
- **Evidence:** Prior path called `CredFree` only after `from_utf16_lossy` on a linear happy path — no RAII; a panic (or later fallible decode) would leak the vault buffer
- **Impact:** Resource leak under panic; unsafe lifetime harder to audit
- **Fix:** Local `CredGuard(*mut CREDENTIALW)` Drop impl always frees (null-safe)
- **Regression:** existing WinCred round-trip / empty / unicode / NUL / oversize retain tests

### CRUD-02 — WinCred missing-delete + DI path under-pinned (`P2`) — **fixed**

- **Where:** `lib.rs` CredMgr tests; `WinCredPasswordStore`
- **Invariant:** Missing delete → `Ok(())` (C# best-effort); `WinCredPasswordStore` must match free helpers
- **Evidence:** Only `FakePasswordStore` had `fake_store_missing_delete_is_ok`; no trait-path pin that `WinCredPasswordStore::{store,read,delete}` ≡ `store_password` / `read_password` / `delete_password`
- **Impact:** Contract drift between DI adapter and free helpers / Fake could ship unnoticed
- **Fix:** `cred_mgr_missing_delete_is_ok_and_trait_matches_free_helpers` (double missing delete + trait ↔ free helper parity); Fake missing delete made idempotent (second call still Ok)
- **Regression:** that test + `fake_store_missing_delete_is_ok`

### CRUD-03 — Fake concurrent races + multi-id isolation under-pinned (`P2`) — **fixed**

- **Where:** `FakePasswordStore` (Mutex map + atomics)
- **Invariant:** Concurrent store/read/delete/oversize-reject must not panic, poison, or echo secrets via Debug; ids are isolated
- **Evidence:** WinCred had a concurrent smoke test; Fake (used by `wormhole-ui` editor persist tests) had neither concurrent stress nor multi-id overwrite isolation
- **Impact:** Mutex/Debug regressions or cross-id clobber could pass single-threaded Fake tests
- **Fix:** `fake_store_concurrent_store_read_delete_no_panic`; `fake_store_multi_id_isolation_and_overwrite` (Debug never contains secrets)
- **Regression:** those tests

### CRUD-04 — Wrong key prefix / N-format under-pinned (`P3`) — **fixed**

- **Where:** `credential_target` / `CREDENTIAL_PREFIX` / `CREDENTIAL_COMMENT`
- **Invariant:** Target is exactly `Wormhole:` + Guid **D**-format (hyphens, lowercase); never N-format; comment matches C#
- **Evidence:** MCP-id prefix test existed; nil UUID + explicit N-format rejection + comment constant were not pinned beside UserName D-format
- **Fix:** `credential_target_uses_prefix_and_d_format_not_n`
- **Regression:** that test + existing MCP target test

### CRUD-05 — Embedded NUL WinCred round-trip untested (`P3`) — **fixed**

- **Where:** `store_password_windows` / `read_password_windows` (length-prefixed UTF-16 blob, not C-string)
- **Invariant:** Embedded `\0` is one UTF-16 unit and must survive CredMgr round-trip
- **Evidence:** Length helper counted NUL; WinCred path never round-tripped `pre\0post-🔒`
- **Impact:** Accidental wide-string APIs that stop at NUL would truncate secrets
- **Fix:** `cred_mgr_embedded_nul_roundtrip`
- **Regression:** that test

### CRUD-06 — `WinCredPasswordStore` rustdoc inverted (`P3`) — **fixed**

- **Where:** `WinCredPasswordStore` module docs
- **Evidence:** Docs claimed free helpers “delegate here”; implementation is the opposite (adapter forwards to free helpers)
- **Fix:** Correct rustdoc — thin `PasswordStore` adapter over free helpers; Fake for tests

---

## Rejected candidates

| ID | Severity | Reason |
|---|---|---|
| REJ-01 | — | C# `DeletePasswordAsync` swallows **all** exceptions; Rust only maps `ERROR_NOT_FOUND` → Ok — intentional fail-closed for real vault failures; docs require missing → Ok only |
| REJ-02 | — | Null `ppCredential` after successful `CredReadW` — not a documented Windows contract; would be UB if it happened; not reachable from our writers |
| REJ-03 | — | Dual `encode_utf16` (ensure count + write collect) — ≤2560 units; rejected again (see size ledger REJ-04) |
| REJ-04 | — | Extract shared `ERROR_NOT_FOUND` helper for read vs delete — different return shapes; not worth churn |
| REJ-05 | — | Fake embedded-NUL test — `String` map trivially preserves NUL; WinCred path is the real risk (pinned) |
| REJ-06 | — | NFC vs NFD different UTF-16 lengths — correct; matches C# code units |
| REJ-07 | — | Size-oracle astral/`chars()*2` — already closed in credmgr-size ledger; still covered by existing tests |
| REJ-08 | — | DPAPI key/tunnel Fake call-count / concurrent work — out of CredMgr CRUD scope |

---

## Adversarial cycles

| Pass | Strategy | Accepted | Result |
|---|---|---|---|
| Adv-1 | Contract / boundary (NUL, prefix) → security (Debug) → Fake concurrency → DI drift → CredFree lifecycle → test resistance | CRUD-01…06 | Fixed; reset |
| Adv-2 | Security → concurrency → integration DI → reverse test oracles → boundary → contract | None | Clean (1/2) |
| Adv-3 | Boundary → state/atomicity → performance → test resistance → security → contract | None | Clean (2/2) |

---

## Simplify passes (iterative-review-simplify)

| Cycle | Reuse | Efficiency | Quality | Disposition |
|---|---|---|---|---|
| 1 | Shared `ensure_password_fits_cred_mgr` on Fake + WinCred; thin WinCred adapter | Dual utf16 encode rejected | CredGuard + missing-delete pins intact | Clean (1/3) |
| 2 | No missed local helpers for NOT_FOUND | No hot-path I/O beyond CredMgr | Prefix / NUL / Fake concurrent pins intact | Clean (2/3) |
| 3 | Same | Same | Diff hygiene / ledger / docs index | Clean (3/3) |

No implementation edits during simplify → adversarial clean passes retained.

---

## Attack lane outcomes (summary)

| Lane | Outcome |
|---|---|
| Oversized password | Pre-write `ensure_password_fits_cred_mgr`; prior value retained (Fake + WinCred) |
| Empty / Unicode / embedded NUL | Round-trips; NUL is length-prefixed (not C-string cut) |
| Debug / Display leaks | `PasswordTooLarge { bytes }`; Fake Debug = lengths + call counts only |
| Wrong key prefix | `Wormhole:` + D-format only; N-format rejected by pin |
| Delete missing | Fake + WinCred → `Ok(())` (idempotent) |
| Fake vs WinCred contract | Same size guard / missing read-delete; WinCred trait ≡ free helpers |
| Concurrent Fake | Mutex map; stress store/read/delete/reject + Debug redaction |

---

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-secrets-win
```

Expected: `89 passed`.
