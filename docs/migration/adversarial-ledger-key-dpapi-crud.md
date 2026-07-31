# Adversarial ledger — private-key / tunnel DPAPI CRUD stubs

**Scope:**
- `rust/crates/wormhole-secrets-win/src/key_tunnel.rs` — `KeyMaterialStore` / `DpapiKeyMaterialStore` / `FakeKeyMaterialStore`; `TunnelPayloadStore` / `DpapiTunnelPayloadStore` / `FakeTunnelPayloadStore`; `write`/`read`/`delete_*_payload` (+ `_under`)
- `delete_key_payload(_under)` / tunnel siblings — confinement before delete; missing → `Ok(())`; never unprotect on delete
- Path confinement under `keys\` / `tunnels\`; `PathNotConfined`; Debug length-only
- Docs: `docs/migration/04-secrets.md`; index in `docs/migration/README.md`

**Out of scope:** HardwarePass / cutover; CredMgr password CRUD; Hello / Bitwarden session; Azure VPN tokencache path helpers (parallel); symlink follow (lexical-only, same class as path ledger); raw `write_protected_file` callers outside key/tunnel helpers.

**Authority:** full adversarial-review-fix (edit in scope)  
**Attack focus:** path escape, empty root, join-replacement, key bytes in Debug/errors, delete-then-read, Fake vs DPAPI contract, concurrent Fake  
**Baseline:** `cargo test -p wormhole-secrets-win` — 78 tests green before review  
**Final:** 94 tests green (includes parallel azure-vpn cache stubs landed in-tree during review)  

Compared against C#: `CredentialService.StorePrivateKeyAsync` / `ReadPrivateKeyAsync` / `DeletePrivateKeyAsync` / tunnel siblings; `FakeCredentialService` defensive copies.

---

## Gate summary

| Gate | Result |
|---|---|
| Adversarial clean passes | **2** consecutive (post-fix + post-simplify re-run) |
| Iterative-review-simplify clean passes | **3** consecutive |
| `cargo test -p wormhole-secrets-win` | **pass** (94) |

---

## Accepted findings

### KEY-01 — Tunnel payload wrote atomic; keys non-atomic (`P2`) — **fixed**

- **Where:** `key_tunnel.rs` `write_tunnel_payload_under` vs `write_key_payload_under`
- **Invariant:** Coherent API matching C# `CredentialService.WriteProtectedAsync` (`File.WriteAllBytesAsync`) for both keys and tunnels; cache files keep `write_protected_file_atomic`
- **Evidence:** Tunnel helper used `write_protected_file_atomic` while keys used `write_protected_file`; docs mixed both
- **Impact:** Divergent crash/overwrite semantics between sibling stores; drift from C# CredentialService
- **Fix:** Both helpers use `write_protected_file`; rustdoc + `04-secrets.md` document C# parity (caches remain atomic)
- **Regression:** existing temp-dir round-trips; docs API sample

### KEY-02 — Delete-never-unprotect under-proven (`P1`) — **fixed**

- **Where:** `delete_key_payload_under` / `delete_tunnel_payload_under` / `delete_protected_file_if_exists`
- **Invariant:** Delete confines then `remove_file` only — never `CryptUnprotectData` / read plaintext
- **Evidence:** Prior tests only deleted valid DPAPI blobs; a regression that unprotect-before-delete would still pass
- **Impact:** Corrupt ciphertext delete would fail closed incorrectly; plaintext could enter memory on delete
- **Fix:** Regression writes garbage ciphertext, asserts read → `DpapiUnprotect`, delete → `Ok(())` + missing path; error text free of markers
- **Regression:** `delete_key_and_tunnel_never_unprotects_corrupt_ciphertext`

### KEY-03 — Fake defensive-copy / concurrent contracts under-pinned (`P2`) — **fixed**

- **Where:** `FakeKeyMaterialStore` / `FakeTunnelPayloadStore`
- **Invariant:** Store/read copy buffers (C# `FakeCredentialService`); concurrent store/read/delete must not panic or echo secrets in Debug
- **Evidence:** Copies existed (`to_vec` / `cloned`) without lifetime regression; Mutex present without concurrent Fake test
- **Impact:** Caller zeroing input/output could silently corrupt fake if copies regress; harness Debug could leak under races
- **Fix:** Zero-after-store / mutate-after-read tests; 8-thread barrier concurrent test; Fake rustdoc documents copies
- **Regression:** `fake_key_and_tunnel_defensive_copies_isolate_caller_buffers`, `fake_key_and_tunnel_concurrent_store_read_delete_debug_safe`

### KEY-04 — Empty-root key helpers + DPAPI overwrite/empty/Debug gaps (`P2`) — **fixed**

- **Where:** hostile-root test; `DpapiKeyMaterialStore` / `DpapiTunnelPayloadStore` tests
- **Invariant:** Empty root rejected for keys as well as tunnels; overwrite + empty blob round-trip; Debug length-only (no root path / secret)
- **Evidence:** Empty root only asserted for tunnel helpers; DPAPI store overwrite/empty/Debug path redaction under-tested
- **Fix:** Empty-root key write/delete in hostile test; overwrite + empty blob; Debug asserts `*_root_len` and no path/secret fragments
- **Regression:** extended `write_read_delete_helpers_reject_hostile_root_before_io`, `dpapi_*_store_crud_under_temp`

### KEY-05 — Docs drift on coherent write / delete / coverage (`P3`) — **fixed**

- **Where:** `docs/migration/04-secrets.md`; module rustdoc
- **Fix:** Path-confinement table, crate map, API sample, coverage paragraph, ledger link; module doc states non-atomic CredentialService write + never-unprotect delete

---

## Rejected candidates

| ID | Severity | Reason |
|---|---|---|
| REJ-01 | — | Merge Fake key/tunnel into one generic — distinct DI types match CredMgr / C# surfaces; churn > clarity |
| REJ-02 | — | Non-atomic write tear on crash — intentional C# CredentialService parity; caches keep atomic |
| REJ-03 | — | Symlink / junction escape past lexical confine — residual; same class as `adversarial-ledger-dpapi-paths` |
| REJ-04 | — | `SecretsError::Io` may embed OS path strings — confined helpers fail closed before I/O on escapes |
| REJ-05 | — | Add Fake corrupt-blob scripting (`CorruptPrivateKeyIds`) — not required for CRUD stub; production returns `DpapiUnprotect` |
| REJ-06 | — | Azure VPN tokencache CRUD (parallel agent) — out of key/tunnel CredentialService CRUD scope; coherent via shared `confined_file_under` |
| REJ-07 | — | Put `Send + Sync` on store traits — adapters in `wormhole-tunnels` already bound concrete types |

---

## Adversarial cycles

| Pass | Strategy | Accepted | Result |
|---|---|---|---|
| Adv-1 | Security (delete/unprotect, Debug) → contract (Fake vs DPAPI / C#) → boundary (empty root) → concurrency | KEY-01..05 | Fixed; reset |
| Adv-2 | Integration drift (`wormhole-tunnels` PayloadStore) → concurrency → reverse boundary → tests-outward | None | Clean (1/2) |
| Adv-3 | Failure atomicity → join-replacement / sibling keys → error redaction | None (sibling-keys test already pins escape) | Clean (2/2) |
| Post-simplify Adv-1 | Rustdoc / defensive-copy assert delta | None | Clean |
| Post-simplify Adv-2 | Fake lifetime + delete-never-unprotect + coherent write still hold | None | Clean (2/2) |

---

## Simplify passes (iterative-review-simplify)

| Cycle | Reuse | Efficiency | Quality | Disposition |
|---|---|---|---|---|
| 1 | — | — | Module/Fake rustdoc omitted coherent write + copies; defensive-copy test used fragile `windows()` | **Fixed** → reset adversarial + simplify |
| 2 | REJ-01 merge Fakes | No hot-path I/O | Contracts + docs aligned | Clean (1/3) |
| 3 | No new shared abstraction | Same | Sibling-keys / corrupt-delete pins intact | Clean (2/3) |
| 4 | REJ-07 Send+Sync on traits | Same | Diff hygiene / ledger / README | Clean (3/3) |

---

## Attack lane outcomes (summary)

| Lane | Outcome |
|---|---|
| Path escape / empty root / join-replacement | `PathNotConfined` before I/O; empty key+tunnel roots; `D:`/`\Windows`/`..` forms; sibling `keys\` untouched |
| Key bytes in Debug/errors | Store Debug = lengths / counts / `*_root_len` only; `PathNotConfined` / `DpapiUnprotect` free of markers |
| Delete then read / never unprotect | Missing delete `Ok(())`; corrupt ciphertext delete succeeds; post-delete read `None` |
| Fake vs DPAPI contract | Missing read `None`; overwrite; empty blob; trait objects; distinct backends; defensive copies |
| Concurrent Fake | Barrier store/read/delete; Debug never echoes secrets |

---

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-secrets-win
```

Expected: **94 passed**.
