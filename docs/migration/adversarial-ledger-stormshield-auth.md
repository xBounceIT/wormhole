# Adversarial ledger — Stormshield SNS auth_glue stub

**Scope:** `rust/crates/wormhole-tunnels/src/providers/auth_glue/stormshield_sns.rs` (+ exports in `auth_glue/mod.rs` / `lib.rs`); docs `07-tunnels-mcp.md` Stormshield notes  
**Authority:** full adversarial-review-fix (edit in scope; do **not** rewrite `StormshieldProvider::establish`)  
**Baseline:** `cargo test -p wormhole-tunnels` green before review  
**Compared against:** C# `StormshieldTunnelProvider` / `StormshieldSettings` / portal `pass = password + otp` (not WatchGuard CRV1 `challenge_response`)

---

## Gate summary

| Gate | Result |
|---|---|
| Adversarial clean passes | **2** consecutive (post-fix; no simplify code delta) |
| Iterative-review-simplify clean passes | **3** consecutive |
| `cargo test -p wormhole-tunnels` | **pass** (lib + lease + sidecar; focused stormshield_sns 14 tests) |

---

## Accepted findings

### SNS-01 — Attack contracts under-pinned (`P2`) — **fixed**

- **Where:** `stormshield_sns.rs` tests
- **Invariant:** password/OTP never in Debug/Display; `compose_sns_auth_password` is `password+otp` (never `challenge_response`); Null fail-closed on OTP spend; Fake queue deterministic; empty OTP rejected
- **Evidence:** Display redaction untested; wrong compositions (OTP-alone / password-without-suffix / CRV1 challenge field) not explicitly rejected; Fake determinism and Null `PortalDownload` cancel unpinned; empty OTP Establish path untested
- **Fix:** Add `sns_otp_goes_into_password_never_challenge_response`, expand `password_debug_and_display_redact_secrets` (Display + request Debug), `fake_is_deterministic_otp_queue`, `fake_rejects_empty_otp_code`, Null cancel for both OTP spends + None path
- **Regression:** those tests

### SNS-02 — Docs omitted dedicated SNS section + ledger (`P3`) — **fixed**

- **Where:** `docs/migration/07-tunnels-mcp.md`, `docs/migration/README.md`
- **Invariant:** shared `wormhole-ovpnproxy` data plane; portal/cache/SSO **UI not wired**; establish not called from SNS stub
- **Evidence:** WatchGuard/Entra had dedicated bullets + ledger links; Stormshield only status/table mentions; README lacked ledger row
- **Fix:** Dedicated Stormshield SNS bullet (`password+otp`, Fake/Null, shared ovpnproxy, UI/establish not wired); link `adversarial-ledger-stormshield-auth.md` in 07 + README
- **Regression:** doc review

---

## Rejected candidates

| ID | Severity | Reason |
|---|---|---|
| REJ-01 | — | Rewrite / wire `StormshieldProvider::establish` — explicitly out of scope |
| REJ-02 | — | Portal HTTPS download / config-hash cache / OTP reuse guard / SSO — not this stub |
| REJ-03 | — | Null cancel when `credentials.use_otp` but `otp_spend == None` — `otp_spend` is authoritative (same as Fake) |
| REJ-04 | — | Zeroize password bytes on `Drop` — hardening beyond C# / stub surface |
| REJ-05 | — | Shared Debug macro with Firebox/Entra secret wrappers — over-abstract |
| REJ-06 | — | Collapse `append_otp_to_password` capacity builder / `resolve` otp_spend dual-if into taste refactors — no clarity win |

---

## Adversarial cycles

1. **Cycle 1 (findings):** SNS-01 accepted → composition / redaction / Null / Fake / empty-OTP regression tests → reset  
2. **Cycle 2 (findings):** SNS-02 accepted → docs SNS section + ledger links → reset  
3. **Clean pass 1:** Security → boundaries → contract (Display/Debug redaction, `password+otp` vs challenge_response, Null fail-closed, Fake queue, empty OTP, docs) — no accepted findings  
4. **Clean pass 2:** Integration drift / concurrency / test resistance (establish not called; shared ovpnproxy docs; Mutex poison recovery; exports) — REJ-01..06 — no accepted findings  

---

## Iterative-review-simplify cycles

1. **Clean pass 1:** reuse / efficiency / quality — no validated findings (REJ-05/06)  
2. **Clean pass 2:** same — no findings  
3. **Clean pass 3:** same — no findings  

---

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-tunnels
```

Focused: `cargo test -p wormhole-tunnels --lib providers::auth_glue::stormshield_sns::`

---

## Residual / out-of-scope notes

- `StormshieldProvider::establish` still expects already-resolved OpenVPN stdin JSON; call `resolve_sns_data_plane_auth` / `StormshieldSnsAuth` + `stormshield_materials_from_sns` when the portal/cache loop is ported.
- **Portal download / config-hash cache / OTP reuse guard / SSO UI are not wired.**
- Data plane remains the **shared** `wormhole-ovpnproxy` binary (no Stormshield-specific sidecar).
