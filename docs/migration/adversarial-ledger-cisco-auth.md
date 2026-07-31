# Adversarial ledger — Cisco aggregate-auth stub

**Scope:** `rust/crates/wormhole-tunnels/src/providers/cisco/aggregate_auth.rs` (+ exports in `cisco/mod.rs` / `providers/mod.rs` / `lib.rs`); docs `07-tunnels-mcp.md` Cisco notes  
**Authority:** full adversarial-review-fix (edit in scope; do **not** rewrite STF/CSTP establish; do **not** wire into `CiscoSecureClientProvider::establish` unless security requires)  
**Baseline:** `cargo test -p wormhole-tunnels` green before / after review  
**Compared against:** C# `CiscoSecureClientSettings` / `CiscoSecureClientSidecarConfig`; Go `answerForm` / `isSecondFactorName` / `secondFactor`

---

## Gate summary

| Gate | Result |
|---|---|
| Adversarial clean passes | **2** consecutive (post-fix; re-run after simplify) |
| Iterative-review-simplify clean passes | **3** consecutive |
| `cargo test -p wormhole-tunnels` | **pass** (179 lib + 15 lease + 24 sidecar) |

---

## Accepted findings

### CISCO-01 — Empty `SecondaryPassword` silently cleared 2FA (`P2`) — **fixed**

- **Where:** `prepare_cisco_sidecar_config` / `CiscoSecondFactor::SecondaryPassword`
- **Invariant:** Explicit second-factor config with empty/whitespace must fail closed (same as empty `TotpSecret`); never silently downgrade to “no 2FA”
- **Evidence:** `empty_to_none(Some(pw))` returned `(None, None)` for `""` / `"  "` while empty TOTP returned `SecondFactorMissing`
- **Fix:** Shared `require_nonempty_second_factor`; both variants error on empty/whitespace
- **Regression:** `prepare_empty_second_factor_secrets_fail_closed`

### CISCO-02 — Empty username / password / whitespace OTP under-pinned (`P2`) — **fixed**

- **Where:** `prepare_cisco_sidecar_config` + Prompt path via `request_second_factor`
- **Invariant:** trim → reject empty host/username/password; Prompt whitespace OTP → Establish (not cancel); errors never echo account password
- **Evidence:** Only empty host was tested; empty user/pass and whitespace Fake OTP lacked regressions
- **Fix:** `prepare_rejects_empty_username_and_password`, `prepare_prompt_whitespace_otp_fails_without_echo`
- **Regression:** those tests

### CISCO-03 — Stdin JSON vs Debug log contract under-pinned (`P2`) — **fixed**

- **Where:** `CiscoSecureClientSidecarConfig` Debug / `to_stdin_json` / module docs
- **Invariant:** Wire JSON may carry secrets for the sidecar; Debug / tracing must never print those values or embed the JSON blob
- **Evidence:** Debug redaction existed; no regression that Debug ≠ stdin JSON; module docs did not forbid tracing stdin JSON
- **Fix:** Module docs + `prepare_debug_redacts_while_stdin_json_keeps_wire_secrets`
- **Regression:** that test

### CISCO-04 — `SecondFactorMissing` said “gateway requested” on prepare (`P3`) — **fixed**

- **Where:** `CiscoAuthError::SecondFactorMissing`
- **Evidence:** Message claimed a gateway challenge when prepare rejected empty configured secondary/TOTP
- **Fix:** Neutral wording for prepare + form-typing paths

### CISCO-05 — Docs omitted client-cert + cisco ledger link (`P3`) — **fixed**

- **Where:** `07-tunnels-mcp.md` status / non-goals / ledgers; `README.md`
- **Invariant:** SAML SSO / CSD / **client cert** unsupported must stay accurate; ledger discoverable
- **Fix:** Status + non-goals mention client cert; link `adversarial-ledger-cisco-auth.md`; README row

### CISCO-06 — Duplicate empty-2FA arms + misleading Totp “prefers” docs (`P3`) — **fixed** (simplify)

- **Where:** `prepare_cisco_sidecar_config` match; `CiscoSecondFactor` / prepare docs; test name
- **Fix:** `require_nonempty_second_factor`; clarify variants are mutually exclusive (Go prefers TOTP only when both wire fields exist); rename test to `prepare_totp_secret_sets_totp_not_secondary`; drop unused `let _` on shape validate

---

## Rejected candidates

| ID | Severity | Reason |
|---|---|---|
| REJ-01 | — | Wire `prepare_cisco_sidecar_config` into `CiscoSecureClientProvider::establish` — explicitly out of scope |
| REJ-02 | — | Implement HTTPS aggregate-auth / STF / CSTP in Rust — user forbade rewrite; stays in Go sidecar |
| REJ-03 | — | Zeroize password bytes on `Drop` — hardening beyond C# / stub surface |
| REJ-04 | — | Add `Display` redaction newtypes for password fields — no `Display` impls today; Debug already redacts |
| REJ-05 | — | Reject port `0` in prepare — sidecar/establish concern; C#/Go default 443 only |
| REJ-06 | — | Call `reject_unsupported_cisco_auth` from prepare — no SAML/CSD/cert flags on `CiscoAuthOptions`; helper for callers |
| REJ-07 | — | ChannelOtpPrompt Cisco-layer test — Null/Memory/Fake cover cancel + submit; channel covered in otp_prompt ledger |
| REJ-08 | — | Redact `server_cert_sha256_pin` in Debug — pin is not a password/TOTP; attack list does not require it |

---

## Adversarial cycles

1. **Cycle 1 (findings):** CISCO-01 / CISCO-02 / CISCO-03 → empty-2FA fail-closed, boundary tests, Debug≠JSON regression + module docs → reset  
2. **Cycle 2 (findings):** CISCO-04 / CISCO-05 → error wording + docs client-cert / ledger links → reset  
3. **Clean pass 1:** Security → boundaries → contract (Debug/redaction, Null cancel, `reject_unsupported_*`, no stdin JSON in tracing, establish unwired) — no accepted findings  
4. **Clean pass 2:** Integration / concurrency / test resistance (exports, OtpPrompt reuse, Fake mutex, unsupported modes + empty 2FA pinned) — REJ-01..08 — no accepted findings  
5. **Post-simplify adversarial re-run:** 2 clean passes on helper + doc/test-name delta — no accepted findings  

---

## Iterative-review-simplify cycles

1. **Cycle 1 (fixes):** reuse (`require_nonempty_second_factor`); efficiency (`cfg.to_stdin_json()?`); quality (Totp docs + test rename) — CISCO-06  
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

Focused: `cargo test -p wormhole-tunnels --lib providers::cisco::aggregate_auth::`

---

## Residual / out-of-scope notes

- `CiscoSecureClientProvider::establish` still takes already-resolved sidecar JSON; prepare is not called inside establish.
- SAML SSO, client certificates, and CSD / HostScan remain unsupported (`reject_unsupported_cisco_auth`).
- Live aggregate-auth XML + STF/CSTP stay in `tools/wormhole-ciscoproxy`.
