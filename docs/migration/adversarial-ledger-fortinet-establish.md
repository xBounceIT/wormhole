# Adversarial ledger — Fortinet establish-path glue

**Scope:** `rust/crates/wormhole-tunnels/src/providers/fortinet/establish.rs` (+ exports in `fortinet/mod.rs` / `providers/mod.rs` / `lib.rs`); docs `07-tunnels-mcp.md` Fortinet establish notes  
**Authority:** full adversarial-review-fix (edit in scope; FakeTunnel / Fake SAML only — **no** live FortiGate / HardwarePass / WebView2)  
**Baseline:** `cargo test -p wormhole-tunnels` green before / after review  
**Compared against:** C# `FortinetTunnelProvider.EstablishAsync` / `FortinetSettings` / `FortinetSidecarConfig` / `SanitizedForAuthenticationMode`

---

## Gate summary

| Gate | Result |
|---|---|
| Adversarial clean passes | **2** consecutive (post-fix; re-run after simplify) |
| Iterative-review-simplify clean passes | **3** consecutive |
| `cargo test -p wormhole-tunnels` | **pass** (319 lib + 21 lease + 24 sidecar) |

---

## Accepted findings

### EST-01 — SSO sidecar shape + secret Debug under-pinned (`P2`) — **fixed**

- **Where:** `resolve_fortinet_sidecar_json` / `build_fortinet_sidecar_config` / `FortinetSidecarConfig` Debug
- **Invariant:** SSO clears username/password/TOTP/realm on sidecar JSON; wire may carry `saml_auth_id` / `svpn_cookie`; Debug never prints password / TOTP / `auth_id` / `SVPNCOOKIE`
- **Evidence:** SSO establish tests only checked `establish_count`; no assertion that stdin JSON carried SAML material or cleared leftovers; Debug tests covered password only
- **Fix:** Added resolve/build regressions for auth_id + cookie paths, TOTP Debug, realm omit on SSO build
- **Regression:** `sso_resolve_clears_password_totp_and_carries_auth_id`, `sso_embedded_resolve_carries_cookie_without_debug_echo`, `saml_sidecar_debug_redacts_auth_id_and_cookie`, `sso_build_clears_realm_even_when_settings_still_carry_one`, extended `settings_and_sidecar_debug_redact_secrets`

### EST-02 — SAML Cancelled / InvalidResult establish mapping under-pinned (`P2`) — **fixed**

- **Where:** `map_saml_error` + `establish_fortinet`
- **Invariant:** Fake cancel → `TunnelError::Cancelled` (no provider call); flow/credential mismatch → `Establish` without echoing cookie/`auth_id`
- **Evidence:** Mapping existed; establish-level regressions missing
- **Fix:** `saml_cancelled_maps_without_provider_call`, `saml_mismatched_credential_fails_without_echoing_cookie`

### EST-03 — Whitespace Host / snake_case blob-as-settings under-pinned (`P2`) — **fixed**

- **Where:** `resolve_fortinet_sidecar_json` host preflight; `parse_fortinet_settings` PascalCase
- **Invariant:** C# `IsNullOrWhiteSpace(Host)`; feeding sidecar snake_case JSON as DPAPI settings must fail closed (empty `Host`), never pretend Up
- **Evidence:** Only `Host:""` tested; `FAKE_FORTINET_SIDECAR_JSON` as settings unpinned
- **Fix:** `whitespace_host_rejects_without_echoing_password`, `snake_case_sidecar_blob_as_settings_fails_closed`

### EST-04 — Malformed settings JSON secret echo under-pinned (`P2`) — **fixed**

- **Where:** `parse_fortinet_settings`
- **Invariant:** Serde failures must not echo the blob (password markers)
- **Evidence:** Empty/invalid path used a fixed message; no regression with a secret marker in truncated JSON
- **Fix:** `invalid_settings_json_does_not_echo_secret`

### EST-05 — External SSO callback port `0` under-pinned (`P2`) — **fixed**

- **Where:** `saml_flow_from_settings` / establish
- **Invariant:** Port `0` → Establish before SAML callback (C# `< 1 or > 65535`; Rust `u16` + explicit `0`)
- **Evidence:** SAML stub tested port `0`; establish glue path unpinned
- **Fix:** `external_sso_port_zero_fails_before_saml`

### EST-06 — Docs / README ledger discoverability (`P3`) — **fixed**

- **Where:** `07-tunnels-mcp.md` adversarial ledger list; `docs/migration/README.md`
- **Fix:** Link `adversarial-ledger-fortinet-establish.md`; README index row

### EST-07 — Repeated SSO field clears in `build_fortinet_sidecar_config` (`P3`) — **fixed** (simplify)

- **Where:** `build_fortinet_sidecar_config`
- **Fix:** Single SSO branch clearing username/password/realm/TOTP (C# `SanitizedForAuthenticationMode` parity); doc comment notes the rule

---

## Rejected candidates

| ID | Severity | Reason |
|---|---|---|
| REJ-01 | — | Live FortiGate / WebView2 / OS-browser SAML UI — explicitly out of scope (stub + Fake only) |
| REJ-02 | — | Merge Fortinet-local lookup traits into shared WG `TunnelConfigLookup` — docs require separate Fortinet establish module |
| REJ-03 | — | Zeroize password / SAML bytes on `Drop` — hardening beyond C# / glue surface |
| REJ-04 | — | Strip `SamlAuthError::Failed` message in `map_saml_error` — callers must keep Failed secret-free (same as SAML ledger REJ-05); diagnostics need the text |
| REJ-05 | — | Capture last stdin blob on `FakeTunnelProvider` — resolve/build tests pin JSON; Fake discard is intentional |
| REJ-06 | — | Reject negative / oversized `Port` in settings — C# `int` + sidecar; not required for establish glue gates |
| REJ-07 | — | Const-dedupe identical port-0 error strings — two call sites; churn without clarity gain |

---

## Adversarial cycles

1. **Cycle 1 (findings):** EST-01..06 accepted → redaction / SSO JSON / cancel-mismatch / whitespace Host / snake_case blob / malformed JSON / port 0 / docs → reset  
2. **Clean pass 1:** Security → boundaries → contract (fail-closed + redaction + C# preflight) — no accepted findings  
3. **Clean pass 2:** Integration / concurrency / test resistance (exports, Fake mutex, resolve pins) — REJ-01..07 — no accepted findings  
4. **Post-simplify adversarial re-run** (SSO clear branch): 2 clean passes on `build_fortinet_sidecar_config` delta — no accepted findings  

---

## Iterative-review-simplify cycles

1. **Cycle 1 (fix):** reuse/clarity — EST-07 single SSO clear branch  
2. **Clean pass 1:** reuse (local traits intentional) / efficiency / quality — no validated findings  
3. **Clean pass 2:** same — no findings  
4. **Clean pass 3:** same — no findings  

---

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-tunnels
```

Focused: `cargo test -p wormhole-tunnels --lib providers::fortinet::establish::`

---

## Residual / out-of-scope notes

- `StubSamlAuthCallback` remains the fail-closed production default until WebView2 / OS-browser UI lands.
- `FortinetProvider::establish` still takes already-resolved sidecar JSON; `establish_fortinet` owns settings → SAML stub → stdin JSON.
- No live FortiGate / HardwarePass in this review.
