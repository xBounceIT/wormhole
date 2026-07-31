# Adversarial ledger — Cisco establish-path glue

**Scope:** `rust/crates/wormhole-tunnels/src/providers/cisco/establish.rs` (+ `cisco/mod.rs` / `providers/mod.rs` exports); docs `07-tunnels-mcp.md` Cisco establish section + README ledger index  
**Authority:** full adversarial-review-fix (edit in scope; **no** live ASA; **no** rewrite of `CiscoSecureClientProvider` / STF/CSTP)  
**Baseline:** `cargo test -p wormhole-tunnels` green before / after review  
**Compared against:** sibling establish glue (Azure / WireGuard / OpenVPN); aggregate-auth stub ledger; Go `wormhole-ciscoproxy` stdin shape

---

## Gate summary

| Gate | Result |
|---|---|
| Adversarial clean passes | **2** consecutive (post-fix; re-run after simplify) |
| Iterative-review-simplify clean passes | **3** consecutive |
| `cargo test -p wormhole-tunnels` | **pass** (340 lib + 21 lease + 24 sidecar) |

---

## Accepted findings

### EST-01 — Auth-path wrong kind under-pinned (`P2`) — **fixed**

- **Where:** `establish_cisco_from_auth` / `load_cisco_snapshot`
- **Invariant:** Wrong config kind / wrong provider kind fail closed on **both** entry points before prepare / secret read / establish
- **Evidence:** Secret-path tests existed; auth path only pinned missing config
- **Fix:** `wrong_config_kind_fails_closed_on_auth_path`, `wrong_provider_kind_fails_closed_on_auth_path` (no secret echo; `get_calls == 0` on wrong provider)
- **Regression:** those tests

### EST-02 — Auth-path prepare fail-closed under-pinned (`P2`) — **fixed**

- **Where:** `establish_cisco_from_auth` → `prepare_cisco_sidecar_config`
- **Invariant:** Empty host/username/password and Prompt without `OtpPrompt` fail before establish; errors never echo account password
- **Evidence:** Azure establish pins empty profile / cancel; Cisco auth path lacked establish-layer regressions
- **Fix:** `auth_path_empty_credentials_fail_without_echo`, `auth_path_prompt_without_otp_fails_before_establish`
- **Regression:** those tests

### EST-03 — Whitespace-only `host` secret under-pinned (`P2`) — **fixed**

- **Where:** `require_cisco_establish_secret` via `establish_cisco`
- **Invariant:** Trimmed-empty `host` rejects without echoing the blob
- **Evidence:** PascalCase editor blob tested; whitespace `host` only covered in `secret_shape` unit tests
- **Fix:** `whitespace_host_secret_rejects_without_echo`
- **Regression:** that test

### EST-04 — Docs / discoverability drift (`P3`) — **fixed**

- **Where:** `07-tunnels-mcp.md` Cisco establish section; README ledger index; `providers/mod.rs` cisco note
- **Invariant:** Fail-closed matrix + SAML/CSD/**client cert** accurate; establish ledger discoverable
- **Evidence:** Mojibake arrows in Cisco section; ledger list linked only `cisco-auth`; README missing establish row; mod.rs omitted client cert
- **Fix:** Rewrite Cisco establish section; link `adversarial-ledger-cisco-establish.md`; README row; mod.rs client-cert note
- **Regression:** doc inspection

### EST-05 — Unsupported-mode alias under-pinned (`P3`) — **fixed**

- **Where:** `reject_cisco_unsupported_auth`
- **Invariant:** Each SAML / CSD / client-cert mode appears in the error text (same as aggregate-auth helper)
- **Evidence:** Establish test asserted “does not support” but not `mode.as_str()`
- **Fix:** Assert `mode.as_str()` in `unsupported_saml_csd_client_cert_fail_closed`
- **Regression:** that test

### EST-06 — Secret-echo / config fixture duplication (`P3`) — **fixed** (simplify)

- **Where:** establish module tests
- **Fix:** `assert_no_secret_echo` + `cisco_config` helpers; module docs name establish reject alias

---

## Rejected candidates

| ID | Severity | Reason |
|---|---|---|
| REJ-01 | — | Wire `prepare_cisco_sidecar_config` into `CiscoSecureClientProvider::establish` — out of scope; provider takes resolved stdin JSON |
| REJ-02 | — | Auto-call `reject_cisco_unsupported_auth` from `establish_cisco_from_auth` — no SAML/CSD/cert flags on `CiscoAuthOptions`; caller helper by design |
| REJ-03 | — | Live ASA / `wormhole-ciscoproxy` process tests — user forbade live ASA |
| REJ-04 | — | Zeroize password bytes on Drop — hardening beyond establish glue / C# parity |
| REJ-05 | — | Stop logging `host` / `secret_len` — non-secret diagnostics; passwords never logged |
| REJ-06 | — | TotpSecret happy-path establish test — SecondaryPassword + Prompt already pin prepare→establish |
| REJ-07 | — | Fix whole-file mojibake outside Cisco section — pre-existing; scoped rewrite of Cisco establish section only |

---

## Adversarial cycles

1. **Cycle 1 (findings):** EST-01 / EST-02 / EST-03 / EST-04 / EST-05 → auth-path kind + prepare regressions, whitespace host, docs/README/mod.rs, mode label assert → reset  
2. **Clean pass 1:** Security → boundaries → contract (Debug/redaction, reject SAML/CSD/cert, no stdin JSON in tracing, both entry points fail-closed) — no accepted findings  
3. **Clean pass 2:** Integration / concurrency / test resistance (exports, shared lookups, Fake mutex, auth-path kinds + empty creds pinned) — REJ-01..07 — no accepted findings  
4. **Post-simplify adversarial re-run:** 2 clean passes on test-helper + module-doc delta — no accepted findings  

---

## Iterative-review-simplify cycles

1. **Cycle 1 (fixes):** reuse (`assert_no_secret_echo`, `cisco_config`); quality (module docs name reject alias) — EST-06  
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

Focused: `cargo test -p wormhole-tunnels --lib providers::cisco::establish`

---

## Residual / out-of-scope notes

- `CiscoSecureClientProvider::establish` still takes already-resolved sidecar JSON; prepare is not called inside the provider.
- SAML SSO, client certificates, and CSD / HostScan remain unsupported (`reject_cisco_unsupported_auth`).
- Live aggregate-auth XML + STF/CSTP stay in `tools/wormhole-ciscoproxy`.
- Broader `07-tunnels-mcp.md` encoding outside the Cisco establish section may still use ASCII `->` replacements from prior corruption; Cisco establish section is UTF-8 arrows / middot / em dash.
