# Adversarial ledger — OpenVPN establish-path glue

**Scope:** `rust/crates/wormhole-tunnels/src/providers/openvpn/establish.rs` (+ `openvpn/mod.rs` exports / `lib.rs` `establish_openvpn` / `FAKE_OPENVPN_SIDECAR_JSON`); docs `07-tunnels-mcp.md` OpenVPN establish section  
**Authority:** full adversarial-review-fix (edit in scope; **separate** from WireGuard API; do **not** spawn live `wormhole-ovpnproxy`)  
**Baseline:** `cargo test -p wormhole-tunnels` green before review  
**Compared against:** WireGuard establish glue (`providers::wireguard::establish`) + `require_openvpn_establish_secret` / C# OpenVPN load order (SQLite metadata → DPAPI secret → provider)

---

## Gate summary

| Gate | Result |
|---|---|
| Adversarial clean passes | **2** consecutive (post-fix) |
| Iterative-review-simplify clean passes | **3** consecutive |
| `cargo test -p wormhole-tunnels` | **pass** (lib + lease + sidecar; focused openvpn establish 15 tests) |

---

## Accepted findings

### OVPN-01 — Empty / whitespace `profile_ovpn` under-pinned at establish (`P2`) — **fixed**

- **Where:** `providers/openvpn/establish.rs` tests
- **Invariant:** Fail-closed before `TunnelProvider::establish` when `profile_ovpn` is empty or whitespace-only (even with `mock:true`); secret never echoed
- **Evidence:** Shape gate lived in `secret_shape`, but establish glue only pinned PascalCase editor blobs / empty byte payload — mock READY risk not pinned on the glue path
- **Fix:** `empty_profile_ovpn_with_mock_fails_before_provider`, `whitespace_profile_ovpn_fails_before_provider`
- **Regression:** those tests (`establish_count == 0`, marker absent)

### OVPN-02 — Invalid / non-object JSON + provider-error echo paths under-pinned (`P2`) — **fixed**

- **Where:** `providers/openvpn/establish.rs` tests
- **Invariant:** Secrets never appear in `TunnelError` Display/Debug; provider errors must not be wrapped with stdin JSON
- **Evidence:** PascalCase path pinned; invalid JSON / JSON array with embedded marker and post-gate `FakeTunnelProvider::fail_next` propagation untested
- **Fix:** `invalid_json_secret_rejects_without_echoing_blob`, `non_object_json_secret_rejects_without_echoing_blob`, `provider_error_propagates_without_wrapping_secret` + shared `assert_no_secret_echo`
- **Regression:** those tests

### OVPN-03 — Docs ledger index incomplete (`P3`) — **fixed**

- **Where:** `docs/migration/07-tunnels-mcp.md`, `docs/migration/README.md`
- **Invariant:** Closed establish reviews are indexed; OpenVPN fail-closed claims match tests
- **Evidence:** OpenVPN establish section existed but lacked ledger link / empty-profile fail-closed detail; README had no row
- **Fix:** Expand OpenVPN fail-closed row; link ledger in section + Adversarial ledgers bullet; README index row
- **Regression:** doc review

### OVPN-04 — Snapshot / secret forward path unpinned (`P2`) — **fixed**

- **Where:** `providers/openvpn/establish.rs` tests
- **Invariant:** `establish_openvpn` must pass `TunnelConfigSnapshot` (incl. `updated_at`) and exact secret bytes to the provider; capturing Debug must not dump the secret
- **Evidence:** `FakeTunnelProvider` ignores args — a wrong snapshot / swapped blob would still "pass"; WireGuard sibling already pins with a capturing double
- **Fix:** `CapturingOvpnProvider` + `establish_forwards_snapshot_and_secret_bytes`
- **Regression:** that test

---

## Rejected candidates

| ID | Severity | Reason |
|---|---|---|
| REJ-01 | — | Merge `establish_openvpn` into WireGuard entry point — explicitly out of scope (separate API) |
| REJ-02 | — | Spawn / assert live `wormhole-ovpnproxy` — forbidden; FakeTunnelProvider / capturing double only |
| REJ-03 | — | Zeroize secret `Vec<u8>` on drop — hardening beyond C# / sibling glue |
| REJ-04 | — | Assert `record.id == config_id` defense-in-depth — Fake/repo get-by-id already keys on id |
| REJ-05 | — | Shared establish harness macro across WG/OpenVPN/Cisco — over-abstract for thin glue |
| REJ-06 | — | Capture tracing subscriber to prove `secret` not logged — `secret_len` only; low ROI |
| REJ-07 | — | Share `CapturingOvpnProvider` with WireGuard capturing type — keep kind-local test doubles |

---

## Adversarial cycles

1. **Cycle 1 (findings):** OVPN-01 / OVPN-02 accepted → empty/whitespace profile + invalid/non-object JSON + provider fail_next echo regressions → reset  
2. **Cycle 2 (findings):** OVPN-03 / OVPN-04 accepted → docs index + capturing forward-path pin → reset  
3. **Clean pass 1:** Security → boundaries → contract (ConfigNotFound / SecretMissing / WrongKind; profile_ovpn gate; Debug/error redaction; snapshot/`updated_at`/secret forward; separate `establish_openvpn`) — no accepted findings  
4. **Clean pass 2:** Integration drift / test resistance / operability (WireGuard lookup reuse; Fake/capturing only; exports; docs ↔ tests; no live ovpnproxy) — REJ-01..07 — no accepted findings  

---

## Iterative-review-simplify cycles

1. **Cycle 1 (finding):** DRY secret-marker payloads via `SECRET_MARKER` / `secret_with_profile` so echo assertions cannot drift from embedded literals → reset  
2. **Clean pass 1:** reuse / efficiency / quality — helpers + capturing Debug already centralize; no further validated findings (REJ-05/07)  
3. **Clean pass 2:** same — no findings  
4. **Clean pass 3:** same — no findings  

*(Post-simplify adversarial re-check: 2 clean passes — security/contract then integration/test-resistance; no new accepted findings.)*

---

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-tunnels
```

Focused: `cargo test -p wormhole-tunnels --lib providers::openvpn::establish::`

---

## Residual / out-of-scope notes

- `OpenVpnProvider::establish` still spawns `wormhole-ovpnproxy` when used in production; this ledger covers the **load → shape-gate → provider** glue with `FakeTunnelProvider` / capturing doubles only.
- Lookup traits / Fakes remain owned by the WireGuard establish module (shared stores); OpenVPN keeps a **separate** `establish_openvpn` entry point.
