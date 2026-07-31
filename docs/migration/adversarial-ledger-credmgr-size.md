# Adversarial ledger — CredMgr 2560-byte password size guard

**Scope:**
- `rust/crates/wormhole-secrets-win/src/cred_mgr.rs` — `password_utf16_byte_len`, `ensure_password_fits_cred_mgr`, `FakePasswordStore`, `WinCredPasswordStore` / `store_password` write path
- `SecretsError::PasswordTooLarge` (`lib.rs`)
- Docs: `docs/migration/04-secrets.md` CredMgr API rows

**Out of scope:** DPAPI / Hello / Bitwarden / path confinement; RDP `MAX_PASSWORD_CHARS` in `wormhole-surface-win`; C# `CredentialService` (no pre-write size guard — Meziantou/`CredWriteW` fail).

**Authority:** full adversarial-review-fix (edit in scope)  
**Compared against:** CredMgr `CRED_MAX_CREDENTIAL_BLOB_SIZE` = 2560 UTF-16 bytes; C# `password.Length * sizeof(char)` / `Encoding.Unicode.GetByteCount`  
**Baseline:** `cargo test -p wormhole-secrets-win` — 72 green before review  
**Final:** 72 passed

---

## Gate summary

| Gate | Result |
|---|---|
| Adversarial clean passes | **2** consecutive (post-fix; re-run after simplify blob-size fix) |
| Iterative-review-simplify clean passes | **3** consecutive |
| `cargo test -p wormhole-secrets-win` | **pass** (72) |

---

## Accepted findings

### CM-01 — Astral / surrogate size contract under-pinned (`P2`) — **fixed**

- **Where:** `cred_mgr.rs` size tests (ASCII / BMP `é` only)
- **Invariant:** Limit is **UTF-16 byte** count via `encode_utf16` × 2 — matching C# code-unit bytes, not UTF-8 and not Unicode scalars
- **Evidence:** `chars().count() * 2` under-counts surrogate pairs: 641 × 🔒 = **2564** UTF-16 bytes but only **1282** under scalar×2 → false **accept**. Mixed `1279×'a' + 🔒` = 2562 UTF-16 bytes but exactly 2560 under scalar×2. Existing oversize tests (ASCII 1281 / BMP accents) would still pass after such a regression
- **Impact:** Oversize astral-plane passwords could reach vault insert / `CredWriteW` if the length helper were “simplified” to scalars
- **Fix:** Document both false-reject (`len()*2`) and false-accept (`chars()*2`) hazards; pin 640×🔒 at-limit, 641×🔒 reject, mixed ASCII+surrogate at-limit/oversize; Fake + WinCred assert prior value retained and errors never echo `🔒`
- **Regression:** `utf16_byte_len_counts_code_units_not_utf8`, `near_limit_multibyte_ascii_mixed_is_accepted_by_size_check`, `ensure_rejects_oversize_without_echoing_secret`, `fake_store_rejects_oversize_before_insert`, `cred_mgr_rejects_oversize_accepts_limit`

### CM-02 — Docs omitted scalar under-count / Fake Debug lengths contract (`P3`) — **fixed**

- **Where:** `docs/migration/04-secrets.md` CredMgr API table
- **Fix:** Document `chars().count()*2` false-accept, at-limit via `>`, and Fake Debug = UTF-16 lengths + call counts only

### SIM-01 — WinCred blob size re-measured independently of buffer (`P3` simplify) — **fixed**

- **Where:** `store_password_windows`
- **Evidence:** Called `password_utf16_byte_len` then separately `password.encode_utf16().collect()` — two sources of truth for blob size vs buffer
- **Fix:** `secret_bytes = secret_w.len() * 2` from the encoded buffer (guard still runs in `store_password` / Fake before any write)

---

## Rejected candidates

| ID | Severity | Reason |
|---|---|---|
| REJ-01 | — | NFC vs NFD different UTF-16 lengths — correct; matches C# stored scalars/code units |
| REJ-02 | — | C# lacks pre-write 2560 guard — Rust is intentionally fail-closed before `CredWriteW` |
| REJ-03 | — | RDP `MAX_PASSWORD_CHARS = 2560` in surface-win — out of scope (chars vs CredMgr bytes) |
| REJ-04 | — | Cache `password_utf16_byte_len` across ensure + write — ≤2560 code units; not worth API churn |
| REJ-05 | — | CredMgr filtered-test flake under `--test-threads` parallel OS vault — full suite green; IDs are distinct |
| REJ-06 | — | Seal / cfg-gate `FakePasswordStore` — other crates need injectable fakes; rustdoc marks test use |

---

## Adversarial cycles

| Pass | Strategy | Accepted | Result |
|---|---|---|---|
| Adv-1 | Contract / Unicode encoding → security (echo) → Fake insert atomicity → test resistance | CM-01, CM-02 | Fixed; reset |
| Adv-2 | Security → WinCred prior-value retain → Fake Debug lengths → docs | None | Clean (1/2) |
| Adv-3 | Boundary (`>` at-limit) → concurrency → integration DI → reverse test oracles | None | Clean (2/2) |
| Post-simplify Adv-A | Blob size = `secret_w.len()*2` still gated; oversize never writes; no secret in errors | None | Clean (1/2) |
| Post-simplify Adv-B | Surrogate / mixed pins still defeat `chars()*2`; Fake reject retains prior | None | Clean (2/2) |

---

## Simplify passes (iterative-review-simplify)

| Cycle | Reuse | Efficiency | Quality | Disposition |
|---|---|---|---|---|
| 1 | Shared `ensure_password_fits_cred_mgr` on Fake + WinCred | Dual length sources on WinCred write | — | **SIM-01** → reset (+ adv re-run) |
| 2 | Guard + `password_utf16_byte_len` stable | Single buffer length for blob | Surrogate pins intact | Clean (1/3) |
| 3 | No missed local helpers | No hot-path I/O beyond CredMgr | Docs / Debug contracts aligned | Clean (2/3) |
| 4 | Same | Same | Diff hygiene / ledger | Clean (3/3) |

---

## Attack lane outcomes (summary)

| Lane | Outcome |
|---|---|
| UTF-16 bytes (not UTF-8 / not scalars) | `encode_utf16().count() * 2`; BMP + astral regressions |
| At-limit allowed; oversize rejected | `bytes > 2560`; 1280 ASCII / 1280 `é` / 640 🔒 accepted |
| Oversize never reaches vault / Fake map | Early `ensure`; prior value retained on reject |
| Error / Fake Debug never echo secret | `PasswordTooLarge { bytes }` only; Debug = lengths + counts |
| Unicode edges | NUL unit=2; surrogate oversize; mixed ASCII+🔒 mis-measure under `chars()*2` |

---

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-secrets-win
```

Expected: `72 passed`.
