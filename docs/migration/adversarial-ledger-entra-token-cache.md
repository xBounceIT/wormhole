# Adversarial ledger — Azure Entra refresh-token DPAPI cache glue

**Scope:** `rust/crates/wormhole-secrets-win/src/azure_vpn_token_cache.rs` (+ `paths` confinement helpers / exports); `rust/crates/wormhole-tunnels/src/providers/auth_glue/entra_refresh_cache.rs` (+ `cache.rs` Azure record encode/decode / max-age); docs `04-secrets.md` / `07-tunnels-mcp.md` / README index  
**Authority:** full adversarial-review-fix (edit in scope; **no** live Entra / WebView2; do **not** merge with keys/tunnels stores)  
**Baseline:** `cargo test -p wormhole-secrets-win -p wormhole-tunnels --lib` green before review  
**Compared against:** C# `AzureVpnTokenCache` / `IAzureVpnTokenCache` (identity hash, 90-day max-age, atomic DPAPI, clear without unprotect)

**Attack focus:** path escape into keys/tunnels; expired token accept; identity mismatch; token in Debug/errors; clear+read without unprotect.

---

## Gate summary

| Gate | Result |
|---|---|
| Adversarial clean passes | **2** consecutive (post-fix; re-run after simplify) |
| Iterative-review-simplify clean passes | **3** consecutive |
| `cargo test -p wormhole-secrets-win -p wormhole-tunnels --lib` | **pass** |

---

## Accepted findings

### ETC-01 — Sibling keys/tunnels path escape under-pinned (`P2`) — **fixed**

- **Where:** `azure_vpn_token_cache.rs` helpers / `DpapiAzureVpnTokenCacheStore`
- **Invariant:** tokencache CRUD confined under `azurevpn-cache\`; must not write into sibling `keys\` / `tunnels\` or accept `..` escape roots
- **Evidence:** Hostile-root test existed; no regression that a successful write leaves sibling dirs empty, or that `azurevpn-cache\..\keys` fail-closes before I/O (tunnel payload store already pinned this pattern)
- **Fix:** `azure_vpn_cache_never_writes_sibling_keys_or_tunnels`
- **Regression:** that test

### ETC-02 — Clear never unprotects under-pinned (`P2`) — **fixed**

- **Where:** `clear_azure_vpn_token_cache_under` / Fake store
- **Invariant:** clear/logout deletes ciphertext without `CryptUnprotectData`; clear+read → miss; Fake clear does not increment read
- **Evidence:** Contract documented; corrupt-ciphertext delete pattern existed for keys/tunnels only
- **Fix:** `clear_never_unprotects_corrupt_ciphertext` + `fake_clear_does_not_read_and_clear_then_read_is_none`; glue-layer clear call-count assert
- **Regression:** those tests

### ETC-03 — Expired / identity miss via Fake store under-pinned (`P2`) — **fixed**

- **Where:** `DpapiAzureVpnRefreshTokenCache::try_load`
- **Invariant:** identity mismatch / >90-day (injectable max-age) / malformed JSON / empty refresh → `Ok(None)` without echoing tokens; clear never reads
- **Evidence:** Helper unit-tested expiry; Windows DPAPI identity mismatch only; removing `try_load` expiry/identity checks would not fail Fake-store coverage
- **Fix:** `fake_store_try_load_rejects_identity_mismatch_expiry_and_clear` + `fake_store_malformed_and_empty_refresh_are_miss_without_echo`
- **Regression:** those tests

### ETC-04 — Docs / ledger index omitted cache-glue review (`P3`) — **fixed**

- **Where:** `docs/migration/README.md`, `04-secrets.md`, `07-tunnels-mcp.md`
- **Invariant:** Closed adversarial reviews indexed; secrets/tunnels docs point at this ledger
- **Evidence:** `adversarial-ledger-entra-token.md` covered provider stub only; no `entra-token-cache` row
- **Fix:** Ledger file + README row; link from `04-secrets` / `07-tunnels-mcp`
- **Regression:** doc review

### ETC-05 — Test import of `wormhole_secrets_win` not feature-gated (`P2`) — **fixed**

- **Where:** `entra_refresh_cache.rs` tests
- **Invariant:** `secrets` feature optional; tests without it must not hard-depend on the crate at module scope
- **Evidence:** Unconditional `use wormhole_secrets_win::AzureVpnTokenCacheStore` at test-module top
- **Fix:** Move trait import inside `#[cfg(feature = "secrets")]` tests
- **Regression:** focused entra_refresh_cache tests (default features)

---

## Rejected candidates

| ID | Severity | Reason |
|---|---|---|
| REJ-01 | — | Wire interactive WebView2 / silent OAuth redeem / `establish_azure_from_entra` persist — explicitly out of scope |
| REJ-02 | — | Merge Azure tokencache into `KeyMaterialStore` / `TunnelPayloadStore` — forbidden; distinct root + entropy |
| REJ-03 | — | Proactive delete of expired/mismatched blobs on miss — C# leaves file; miss → popup |
| REJ-04 | — | Reject future `cachedAtUtc` (clock skew) — C# accepts; Entra enforces real lifetime |
| REJ-05 | — | Zeroize refresh tokens on Drop — hardening beyond C# / glue surface |
| REJ-06 | — | Rename `map_store_write` error text for clear — cosmetic; no secret echo |
| REJ-07 | — | Trim identity fields before hash — C# does not trim; would break parity |
| REJ-08 | — | Shared Debug/assert helper for token-leak checks — over-abstract for a few tests |

---

## Adversarial cycles

1. **Cycle 1 (findings):** ETC-01/02/03 accepted → sibling escape + clear-without-unprotect + Fake-store identity/expiry/clear regressions → reset  
2. **Cycle 2 (findings):** ETC-04/05 accepted → docs ledger + feature-gated secrets import → reset  
3. **Clean pass 1:** Security → clear+read → path escape → Debug/errors (independent order) — no accepted findings  
4. **Clean pass 2:** Contract/C# parity → integration drift → test resistance (Fake vs DPAPI; max-age boundary; identity hash) — REJ-01..08 — no accepted findings  
5. **Post-simplify adversarial re-run:** 2 clean passes on sibling-loop + import hygiene delta — no accepted findings  

---

## Iterative-review-simplify cycles

1. **Cycle 1 (fixes):** reuse (drop redundant `encode_azure_token_cache_json` test import — already via `super::*`); quality (sibling escape loop drops duplicate `op` tuple)  
2. **Clean pass 1:** reuse / efficiency / quality — no validated findings  
3. **Clean pass 2:** same — no findings  
4. **Clean pass 3:** same — no findings  

---

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-secrets-win -p wormhole-tunnels --lib
```

Focused:

```powershell
cargo test -p wormhole-secrets-win --lib azure_vpn_token_cache::
cargo test -p wormhole-tunnels --lib providers::auth_glue::entra_refresh_cache::
```

---

## Residual / out-of-scope notes

- Interactive Microsoft sign-in popup / silent refresh redeem remain unwired.
- `FakeAzureVpnRefreshTokenCache` intentionally ignores identity / max-age (concrete `DpapiAzureVpnRefreshTokenCache` owns those).
- Opaque blob store stays in `wormhole-secrets-win`; JSON schema / identity / max-age stay in `wormhole-tunnels::auth_glue`.
