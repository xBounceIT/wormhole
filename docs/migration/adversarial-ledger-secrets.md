# Adversarial ledger — `wormhole-secrets-win`

**Scope:** `rust/crates/wormhole-secrets-win/`, `docs/migration/04-secrets.md`, minimal `rust/Cargo.toml` windows feature glue  
**Authority:** full adversarial-review-fix (edit in scope)  
**Baseline:** `cargo test -p wormhole-secrets-win` — 11 tests green before review  
**Final:** 25 tests green  

Compared against C#: `Services/CredentialService.cs`, `Helpers/AppPaths.cs`, `DpapiAppAuthenticationDataProtector`, `BitwardenBrowserSharedStorage`, Azure/WatchGuard/Stormshield caches, `BitwardenCliVaultClient.SanitizeError`.

---

## Gate summary

| Gate | Result |
|---|---|
| Adversarial clean passes | **2** consecutive (post-fix + post-simplify re-run) |
| Iterative-review-simplify clean passes | **3** consecutive |
| `cargo test -p wormhole-secrets-win` | **pass** (25) |

---

## Accepted findings

### SEC-01 — CredMgr size used UTF-8 length (`P1`) — **fixed**

- **Where:** `cred_mgr.rs` `store_password_windows` used `password.len() * 2`
- **Invariant:** CredMgr limit is **2560 UTF-16 bytes** (Meziantou / Win7+)
- **Evidence:** 1280 × `é` is 2560 UTF-16 bytes but 5120 under `len()*2` → false reject
- **Impact:** Near-limit non-ASCII passwords rejected despite fitting
- **Fix:** `password_utf16_byte_len` via `encode_utf16().count() * 2`
- **Regression:** `utf16_byte_len_*`, `cred_mgr_rejects_oversize_accepts_limit`

### SEC-02 — Atomic replace used delete-then-rename (`P1`) — **fixed**

- **Where:** `dpapi.rs` `write_protected_file_atomic`
- **Invariant:** C# caches use `File.Move(..., overwrite: true)` / `MoveFileEx(REPLACE_EXISTING)` — no delete gap
- **Evidence:** Prior path `rename` fails on existing Windows dest → `remove_file` then `rename` (crash window + orphan `.tmp` on failure)
- **Fix:** `MoveFileExW(MOVEFILE_REPLACE_EXISTING)`; temp name `{path}.{guid:N}.tmp`; best-effort tmp delete on error; workspace feature `Win32_Storage_FileSystem`
- **Regression:** `atomic_write_overwrites_existing_without_delete_gap`, `atomic_temp_name_matches_csharp_suffix_pattern`

### SEC-03 — Redaction missed C# sanitize forms (`P1`) — **fixed**

- **Where:** `redact.rs`
- **Invariant:** Match `BitwardenCliVaultClient.SanitizeError` (`(?i)`, `--session=` / `--code=`, optional spaces around env `=`)
- **Evidence:** Case variants and `=` forms left secrets visible; byte-slice truncate panicked on multi-byte UTF-8
- **Fix:** Case-insensitive flag/env redaction; char-based truncate (500 scalars)
- **Regression:** `equals_forms_and_case_insensitive`, `truncate_does_not_panic_on_multibyte_boundary`, `bare_equals_without_value_left_alone`

### SEC-04 — CredMgr error path used `GetLastError` after `Result` (`P2`) — **fixed**

- **Where:** `read_password_windows` / `delete_password_windows`
- **Evidence:** Footgun after `windows` crate `Result` conversion; compare `ERROR_NOT_FOUND.to_hresult()` on the `Error`
- **Fix:** Match on `CredReadW`/`CredDeleteW` `Result`; shared `win32::win32_err`

### SEC-05 — Empty / Unicode CredMgr + error Display safety under-tested (`P2`) — **fixed**

- **Where:** tests / empty blob pointer
- **Fix:** Null blob pointer when password empty; regressions for empty+Unicode round-trip, concurrent store/read, `SecretsError` Display/Debug free of secret payloads, wrong-entropy error text

### SEC-06 — Docs drift on UTF-16 / redaction / atomic write (`P3`) — **fixed**

- **Where:** `docs/migration/04-secrets.md`
- **Fix:** Document `password_utf16_byte_len`, MoveFileEx atomic write, case-insensitive redaction, error safety

---

## Rejected candidates

| ID | Severity | Reason |
|---|---|---|
| REJ-01 | — | `Some(&[])` entropy treated as `None` — unused; callers pass `None` or named/tunnel bytes |
| REJ-02 | — | CredMgr last-writer-wins under concurrency — matches OS / C# semantics |
| REJ-03 | — | `from_utf16_lossy` on read — acceptable for corrupt blobs; no secret logging |
| REJ-04 | — | Path traversal via Uuid helpers — `guid_n` is hex-only; rejected as unreachable |
| REJ-05 | — | Fortinet DPAPI file — non-goal (no persisted Fortinet DPAPI by design) |
| REJ-06 | — | Full lowercase copy in redaction — log-sized; not worth complexity |
| REJ-07 | — | Speculative LocalMachine CredMgr elevation failures — parity with C# Meziantou |

---

## Simplify passes (iterative-review-simplify)

| Cycle | Reuse | Efficiency | Quality | Disposition |
|---|---|---|---|---|
| 1 | Duplicated HRESULT decode + entropy blob setup + parent mkdir | — | — | **Fixed:** `win32` module, `with_optional_entropy`, `ensure_parent` |
| 2 | Fold unused `win32_code` into `win32_err` | No findings | No findings | **Fixed** (tiny), then reset |
| 3–5 | No findings | No findings | No findings | **3 clean** |

---

## Adversarial cycles (post-simplify re-run)

| Pass | Strategy | Accepted |
|---|---|---|
| 1 | Security / redaction / atomic I/O first | none |
| 2 | Tests-outward + C# integration drift (entropy table, paths, CredMgr D-format) | none |

---

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-secrets-win
```

Expected: `25 passed`.
