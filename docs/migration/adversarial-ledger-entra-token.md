# Adversarial ledger — Azure VPN EntraTokenProvider stub

**Scope:** `rust/crates/wormhole-tunnels/src/providers/auth_glue/entra_token.rs` (+ exports in `auth_glue/mod.rs` / `lib.rs`); docs `07-tunnels-mcp.md` Entra notes  
**Authority:** full adversarial-review-fix (edit in scope; do **not** wire Azure `establish` / WebView2 popup)  
**Baseline:** `cargo test -p wormhole-tunnels` green before review  
**Compared against:** C# `IAzureVpnAuthService` / `AzureVpnTokenResult` / `AzureVpnTokenCache` path (`username`=`AzureAD`, password=access token)

---

## Gate summary

| Gate | Result |
|---|---|
| Adversarial clean passes | **2** consecutive (post-fix; re-run after simplify) |
| Iterative-review-simplify clean passes | **3** consecutive |
| `cargo test -p wormhole-tunnels` | **pass** (lib + lease + sidecar; focused entra 16 tests) |

---

## Accepted findings

### ENTRA-01 — Cache path / no-disk contracts under-pinned (`P2`) — **fixed**

- **Where:** `entra_token.rs` `azure_vpn_refresh_token_cache_path` + stub acquire/materials path
- **Invariant:** cache path confined under `azurevpn-cache\<id:N>.tokencache`; stub never writes token bytes to disk
- **Evidence:** path test used substring `contains("azurevpn-cache")` (false-positive risk); no regression that acquire / `request_entra_access_token` / `azure_materials_from_entra` create or mutate the tokencache file
- **Fix:** Assert parent `file_name() == "azurevpn-cache"` and exact `{simple}.tokencache` name; add `stub_never_writes_tokencache_bytes_to_disk`; add `fake_provider_is_deterministic_queue`
- **Regression:** those tests

### ENTRA-02 — Docs omitted Entra ledger + refresh-drop semantics (`P3`) — **fixed**

- **Where:** `docs/migration/07-tunnels-mcp.md`, `docs/migration/README.md`
- **Invariant:** WebView2 popup not wired; hook returns access only (no tokencache write)
- **Evidence:** ledger list lacked `adversarial-ledger-entra-token.md`; `request_entra_access_token` silently dropped refresh without doc callout
- **Fix:** Link ledger (status + adversarial list + README); document access-only / no-write; module docs note refresh discard
- **Regression:** doc review + existing e2e password ≠ refresh test

### ENTRA-03 — `EntraTokenResult` Debug bypassed `RefreshToken` redactor (`P3`) — **fixed** (simplify)

- **Where:** `EntraTokenResult` `Debug`
- **Evidence:** hardcoded `map(|_| "[REDACTED]")` instead of reusing `RefreshToken`’s `Debug`
- **Fix:** `.field("refresh_token", &self.refresh_token)`; explicit `refresh_token: _` discard in `request_entra_access_token`
- **Regression:** `token_result_and_response_debug_redact`

---

## Rejected candidates

| ID | Severity | Reason |
|---|---|---|
| REJ-01 | — | Wire WebView2 / WinRT interactive popup or Azure `establish` — explicitly out of scope |
| REJ-02 | — | DPAPI refresh-token cache read/write in this stub — path + `auth_glue::cache` decode only |
| REJ-03 | — | `ChannelEntraTokenProvider` — `EntraTokenError::ChannelClosed` reserved for future UI host |
| REJ-04 | — | Zeroize token bytes on `Drop` — hardening beyond C# / stub surface |
| REJ-05 | — | Shared Debug macro for `AccessToken`/`RefreshToken` — over-abstract (same as OTP REJ-06) |
| REJ-06 | — | Avoid re-alloc when trim is a no-op in `request_entra_access_token` — micro-opt, hurts clarity |

---

## Adversarial cycles

1. **Cycle 1 (findings):** ENTRA-01 accepted → path parent assertion + no-disk + Fake deterministic tests → reset  
2. **Cycle 2 (findings):** ENTRA-02 accepted → docs ledger link + access-only / WebView2 wording → reset  
3. **Clean pass 1:** Security → boundaries → contract (redaction, trim, Null, AzureAD password, path, no-disk, docs) — no accepted findings  
4. **Clean pass 2:** Integration drift / concurrency / test resistance (not called from establish; secrets path match; Mutex poison recovery) — REJ-01..06 — no accepted findings  
5. **Post-simplify adversarial re-run:** 2 clean passes on Debug reuse + explicit refresh discard delta — no accepted findings  

---

## Iterative-review-simplify cycles

1. **Cycle 1 (fixes):** reuse (`EntraTokenResult` Debug → `RefreshToken`); quality (explicit `refresh_token: _` discard)  
2. **Clean pass 1:** reuse / efficiency / quality — no validated findings  
3. **Clean pass 2:** same — no findings  
4. **Clean pass 3:** same — no findings  

---

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-tunnels
```

Focused: `cargo test -p wormhole-tunnels --lib providers::auth_glue::entra_token::`

---

## Residual / out-of-scope notes

- Azure `establish` still takes already-resolved OpenVPN stdin JSON / materials; call `request_entra_access_token` + `azure_materials_from_entra` when the provider path is ported.
- **Interactive WebView2 / WinRT Microsoft sign-in popup is not wired.**
- Refresh-token DPAPI cache glue lives in `auth_glue::entra_refresh_cache` (`AzureVpnRefreshTokenCache` + Fake / DPAPI); opaque confined blobs in `wormhole-secrets-win::AzureVpnTokenCacheStore`. Silent OAuth redeem + wiring into `establish_azure_from_entra` remain follow-ups.
