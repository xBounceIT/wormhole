# Adversarial ledger — Azure VPN establish-path glue

**Scope:** `rust/crates/wormhole-tunnels/src/providers/azure_vpn/establish.rs` (+ `azure_vpn/mod.rs` exports / `lib.rs` `establish_azure` / `establish_azure_from_entra` / `AzureVpnEstablishOptions` / `FAKE_AZURE_VPN_SIDECAR_JSON`); docs `07-tunnels-mcp.md` Azure establish section  
**Authority:** full adversarial-review-fix (edit in scope; **separate** from WireGuard / OpenVPN / Cisco / Fortinet APIs; do **not** spawn live Azure / Entra popup / `wormhole-ovpnproxy`)  
**Baseline:** `cargo test -p wormhole-tunnels` green before review  
**Compared against:** Stormshield / OpenVPN establish glue + `require_openvpn_establish_secret` / C# Azure load order (SQLite metadata → Entra access token as OpenVPN password with username `AzureAD` → provider)

---

## Gate summary

| Gate | Result |
|---|---|
| Adversarial clean passes | **2** consecutive (post-fix; re-run after simplify) |
| Iterative-review-simplify clean passes | **3** consecutive |
| `cargo test -p wormhole-tunnels` | **pass** (lib + lease + sidecar; focused azure_vpn establish 24 tests) |

---

## Accepted findings

### AZURE-EST-01 — Fail-closed / AzureAD contracts under-pinned (`P2`) — **fixed**

- **Where:** `providers/azure_vpn/establish.rs` (+ shared `establish_with_secret`)
- **Invariant:** Missing config/secret / wrong kind fail closed before Entra or establish; Entra path builds `username`=`AzureAD` + access-token password stdin; empty profile cancels Entra; Null Entra → `Cancelled`; tokens never in Debug/errors; establish does not write tokencache
- **Evidence:** Empty secret / Entra-path WrongKind untested; AzureAD contract rebuilt offline instead of capturing provider stdin; no establish-layer no-disk pin
- **Fix:** `establish_with_secret` shape-gates both paths (Stormshield parity); `RecordingAzureProvider`; regressions for empty secret, Entra wrong kind, AzureAD stdin capture, tokencache no-write, empty-options Debug
- **Regression:** those tests

### AZURE-EST-02 — Docs ledger index incomplete (`P3`) — **fixed**

- **Where:** `docs/migration/07-tunnels-mcp.md`, `docs/migration/README.md`
- **Invariant:** Closed establish reviews indexed; Azure fail-closed claims match tests (incl. empty secret / shape-gate on Entra path); no mojibake arrows
- **Evidence:** Azure establish section lacked ledger link; README had no row; Adversarial ledgers bullet omitted azure-establish
- **Fix:** Repair Azure section arrows + fail-closed/shape-gate wording; link ledger in section + list; README row
- **Regression:** doc review

### AZURE-EST-03 — Empty / whitespace `profile_ovpn` + echo paths under-pinned (`P2`) — **fixed**

- **Where:** `providers/azure_vpn/establish.rs` tests
- **Invariant:** Fail-closed before establish when stored secret has empty/whitespace `profile_ovpn` (even with `mock:true`); invalid JSON and provider `fail_next` never echo secret markers
- **Evidence:** OpenVPN sibling pinned these; Azure only covered PascalCase editor blobs / empty byte payload
- **Fix:** `empty_profile_ovpn_with_mock_fails_before_provider`, `whitespace_profile_ovpn_fails_before_provider`, `invalid_json_secret_rejects_without_echoing_blob`, `provider_error_propagates_without_wrapping_secret` + `SECRET_MARKER` / `assert_no_secret_echo`
- **Regression:** those tests

### AZURE-EST-04 — Snapshot / secret forward path under-pinned (`P2`) — **fixed**

- **Where:** `RecordingAzureProvider` + establish tests
- **Invariant:** Both entry points forward `TunnelConfigSnapshot` (incl. `updated_at`) and exact stdin bytes; capturing `Debug` must not dump tokens/profile
- **Evidence:** `FakeTunnelProvider` ignores args — wrong snapshot / swapped blob would still "pass"
- **Fix:** Capture `(snapshot, secret)`; `establish_forwards_snapshot_and_secret_bytes`; Entra-path capture asserts snapshot + AzureAD JSON
- **Regression:** those tests

### AZURE-EST-05 — Redundant `establish_path` / unused capture field (`P3`) — **fixed** (simplify)

- **Where:** `establish_with_secret` / `RecordingAzureProvider`
- **Evidence:** Dynamic path field duplicated Stormshield’s single info line; `last_config_name` written never asserted
- **Fix:** Drop path arg (one `"establishing Azure VPN tunnel"` line); capture only snapshot+secret
- **Regression:** existing forward / Entra stdin tests

---

## Rejected candidates

| ID | Severity | Reason |
|---|---|---|
| REJ-01 | — | Wire interactive Entra WebView2 / live Azure VPN / ovpnproxy — explicitly out of scope |
| REJ-02 | — | Persist refresh token inside `establish_azure_from_entra` — Entra stub discards refresh; cache writer is separate |
| REJ-03 | — | Merge Azure entry points into OpenVPN / WireGuard API — separate module by design |
| REJ-04 | — | Zeroize access-token / secret `Vec<u8>` on drop — hardening beyond C# / sibling glue |
| REJ-05 | — | Share `RecordingAzureProvider` with OpenVPN `CapturingOvpnProvider` — keep kind-local test doubles |
| REJ-06 | — | Capture tracing subscriber to prove secret not logged — `secret_len` only; low ROI |
| REJ-07 | — | Empty tenant/audience/client_id fail-closed — identity metadata passed through; Entra Fake ignores them |

---

## Adversarial cycles

1. **Cycle 1 (findings):** AZURE-EST-01 / AZURE-EST-02 accepted → shape-gate helper + fail-closed / AzureAD / tokencache / docs → reset  
2. **Cycle 2 (findings):** AZURE-EST-03 / AZURE-EST-04 accepted → empty/whitespace profile + invalid JSON + fail_next echo + snapshot forward → reset  
3. **Clean pass 1:** Security → boundaries → contract (ConfigNotFound / SecretMissing / WrongKind; AzureAD password; Debug/error redaction; no tokencache; profile_ovpn gate) — no accepted findings  
4. **Clean pass 2:** Integration drift / test resistance / operability (Stormshield/OpenVPN parity; Fake/Recording only; exports; docs ↔ tests; no live Azure/Entra) — REJ-01..07 — no accepted findings  
5. **Post-simplify adversarial re-run:** 2 clean passes on dropped path field + capture simplification — no accepted findings  

---

## Iterative-review-simplify cycles

1. **Cycle 1 (fixes):** AZURE-EST-05 — drop `establish_path`; drop unused `last_config_name`; DRY `SECRET_MARKER` / `assert_no_secret_echo`  
2. **Clean pass 1:** reuse / efficiency / quality — no further validated findings (REJ-05)  
3. **Clean pass 2:** same — no findings  
4. **Clean pass 3:** same — no findings  

---

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-tunnels
```

Focused: `cargo test -p wormhole-tunnels --lib providers::azure_vpn::`

---

## Residual / out-of-scope notes

- `AzureVpnProvider::establish` still expects already-resolved OpenVPN stdin JSON; Entra prepare stays in glue (`establish_azure_from_entra`).
- **Interactive Microsoft sign-in / WebView2 popup is not wired.**
- Refresh-token DPAPI persist/load/clear lives in `auth_glue` cache helpers — **not** invoked by establish-path glue.
- Data plane remains the **shared** `wormhole-ovpnproxy` binary.
