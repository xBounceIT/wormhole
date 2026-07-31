# Adversarial ledger — Stormshield SNS establish-path glue

**Scope:** `rust/crates/wormhole-tunnels/src/providers/stormshield/establish.rs` (+ `stormshield/mod.rs` exports); docs `07-tunnels-mcp.md` Stormshield establish section + README / feature-matrix  
**Authority:** full adversarial-review-fix (edit in scope; do **not** rewrite `StormshieldProvider::establish` OpenVPN spawn; **no** live SNS / portal / cache / SSO)  
**Baseline:** `cargo test -p wormhole-tunnels` green before review  
**Compared against:** C# Stormshield load→auth→ovpnproxy order; Azure establish empty-profile-before-auth parity; WatchGuard establish fail-closed shape

---

## Gate summary

| Gate | Result |
|---|---|
| Adversarial clean passes | **2** consecutive (post-fix; re-run after simplify — no simplify code delta) |
| Iterative-review-simplify clean passes | **3** consecutive |
| `cargo test -p wormhole-tunnels` | **pass** (lib + lease + sidecar; focused stormshield establish **15** unit tests with `secrets` feature) |

---

## Accepted findings

### SSE-01 — Empty profile spent SNS OTP before shape fail (`P2`) — **fixed**

- **Where:** `establish_stormshield_sns`
- **Invariant:** Single-use OTP must not be consumed when `profile_ovpn` is empty/whitespace (Azure `establish_azure_from_entra` fails before Entra for the same reason)
- **Evidence:** Auth `resolve` ran before `stormshield_sns_to_sidecar_json` / shape gate; Fake OTP queue would dequeue on blank profile
- **Fix:** Trim-empty check → `TunnelError::Establish` **before** `StormshieldSnsAuth::resolve`
- **Regression:** `empty_profile_fails_before_sns_auth`

### SSE-02 — SNS-path attack contracts under-pinned (`P2`) — **fixed**

- **Where:** establish unit tests
- **Invariant:** Wrong config/provider kind fail closed on SNS path without auth; Null cancel for `DataPlane` **and** `PortalDownload`; `password+otp` concat (never `challenge_response`) reaches provider stdin; secrets never in Debug/error text
- **Evidence:** Kind/provider negatives only covered secret-store path; Null only `DataPlane`; concat test only checked Fake Debug (FakeTunnelProvider discards blob)
- **Fix:** Extend kind/provider + Null tests; `RecordingStormshieldProvider` asserts composed password on SNS establish
- **Regression:** those strengthened tests

### SSE-03 — Missing establish ledger / README / matrix drift (`P3`) — **fixed**

- **Where:** `docs/migration/adversarial-ledger-stormshield-establish.md`, `README.md`, `07-tunnels-mcp.md`, `feature-matrix.md`
- **Invariant:** Establish-path glue discoverable; matrix not “Pending” once stub ships
- **Evidence:** Auth ledger existed; establish section had no ledger See-link; feature-matrix still said “establish wiring Pending”
- **Fix:** This ledger + README row + 07 See/ledgers links + matrix wording
- **Regression:** doc review

---

## Rejected candidates

| ID | Severity | Reason |
|---|---|---|
| REJ-01 | — | Wire portal HTTPS / config-hash cache / OTP reuse guard / SSO UI — explicitly out of scope |
| REJ-02 | — | Rewrite `StormshieldProvider::establish` OpenVPN spawn — forbidden by review authority |
| REJ-03 | — | Add `take_last` to shared `FakeTunnelProvider` — prefer local recording double (Azure pattern) |
| REJ-04 | — | Empty-profile gate on WatchGuard CRV1/portal establish — separate provider; not this scope |
| REJ-05 | — | Collapse duplicate `establish_with_secret` across ovpn-backed establish modules — cross-provider churn |
| REJ-06 | — | Mojibake cleanup across all of `07-tunnels-mcp.md` — pre-existing encoding; not Stormshield-establish-specific |

---

## Adversarial cycles

1. **Cycle 1 (findings):** SSE-01 / SSE-02 / SSE-03 accepted → empty-profile gate + SNS-path regressions + docs/ledger → reset  
2. **Clean pass 1:** Security → boundaries → contract (redaction, Null both spends, kind gates, OTP not spent on empty profile, `password+otp`) — no accepted findings  
3. **Clean pass 2:** Integration drift / concurrency / test resistance (exports; shared lookups; Fake Debug; no live SNS; recording provider length-only Debug) — REJ-01..06 — no accepted findings  

---

## Iterative-review-simplify cycles

1. **Clean pass 1:** reuse / efficiency / quality — no validated findings (REJ-03/05)  
2. **Clean pass 2:** same — no findings  
3. **Clean pass 3:** same — no findings  

---

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-tunnels
```

Focused: `cargo test -p wormhole-tunnels --lib providers::stormshield::establish::` (**15** passed).

---

## Residual / out-of-scope notes

- Portal download / config-hash cache / OTP reuse guard / SSO UI remain **not wired**; caller supplies profile text.
- Data plane remains the **shared** `wormhole-ovpnproxy` binary (no Stormshield-specific sidecar).
- `StormshieldProvider::establish` still expects already-resolved OpenVPN sidecar JSON after this glue.
