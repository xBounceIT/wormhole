# Adversarial ledger — WatchGuard Firebox auth stub

**Scope:** `rust/crates/wormhole-tunnels/src/providers/watchguard/firebox_auth.rs` (+ exports in `watchguard/mod.rs` / `providers/mod.rs` / `lib.rs`); docs `07-tunnels-mcp.md` WatchGuard notes  
**Authority:** full adversarial-review-fix (edit in scope; do **not** rewrite `WatchguardProvider::establish` OpenVPN path)  
**Baseline:** `cargo test -p wormhole-tunnels` green (167+ lib tests) before review  
**Compared against:** C# `WatchguardTunnelProvider` credential / CRV1 + portal `sslvpn_logon` password quirk (`RunPreAuthLoopAsync` / `ResolveViaStoredProfileAsync`)

---

## Gate summary

| Gate | Result |
|---|---|
| Adversarial clean passes | **2** consecutive (post-fix; re-run after simplify) |
| Iterative-review-simplify clean passes | **3** consecutive |
| `cargo test -p wormhole-tunnels` | **pass** (lib + lease + sidecar; focused watchguard 20 tests) |

---

## Accepted findings

### WG-01 — Null / cancel fail-closed under-pinned on `resolve_firebox_*` (`P2`) — **fixed**

- **Where:** `resolve_firebox_crv1_sidecar_json` / `resolve_firebox_portal_sidecar_json`
- **Invariant:** OTP via `auth_glue::request_otp` / `request_second_factor`; `NullOtpPrompt` / user cancel → `TunnelError::Cancelled` (fail-closed); never echo password
- **Evidence:** only `request_firebox_second_factor(&NullOtpPrompt, …)` was regression-tested; resolve wrappers share the prompt path but lacked end-to-end cancel coverage
- **Fix:** `resolve_crv1_and_portal_null_otp_fail_closed`
- **Regression:** that test

### WG-02 — Empty OTP through resolve under-pinned (`P2`) — **fixed**

- **Where:** `resolve_firebox_crv1_sidecar_json` + `request_second_factor` empty trim
- **Invariant:** whitespace-only OTP → `TunnelError::Establish`; errors never echo password / whitespace
- **Evidence:** otp_prompt layer covered empty; Firebox resolve path did not
- **Fix:** `resolve_crv1_empty_otp_fails_without_echo`
- **Regression:** that test

### WG-03 — CRV1 vs portal OTP field fork under-pinned (`P2`) — **fixed**

- **Where:** `firebox_materials_crv1` vs `firebox_materials_portal` / `portal_openvpn_password`
- **Invariant:** same OTP must not silently land in the wrong OpenVPN field (CRV1 → `challenge_response` + account `password`; portal → OTP as `password`, no challenge)
- **Evidence:** path-specific tests existed; no single comparative regression; module/docs under-stated the fork
- **Fix:** `crv1_vs_portal_otp_field_placement_diverges`; module + `07-tunnels-mcp.md` field-fork callouts
- **Regression:** that test + doc review

### WG-04 — `validated` stripped surrounding password spaces (`P2`) — **fixed**

- **Where:** `FireboxCredentials::validated`
- **Invariant:** C# `IsNullOrWhiteSpace` rejects whitespace-only but does **not** trim `settings.Password` for the wire
- **Evidence:** Rust trimmed both username and password into `Self::new(user_t, pass_t)`
- **Fix:** trim username for wire; reject whitespace-only password without stripping stored spaces
- **Regression:** `validated_trims_username_preserves_password_spaces`

### WG-05 — Missing WatchGuard auth ledger / README link (`P3`) — **fixed**

- **Where:** `docs/migration/07-tunnels-mcp.md`, `docs/migration/README.md`
- **Invariant:** shared `wormhole-ovpnproxy`; Firebox HTTP/SAML UI not wired; review ledger discoverable
- **Evidence:** status bullets existed; adversarial list / README lacked `adversarial-ledger-watchguard-auth.md`
- **Fix:** link this ledger; keep HTTP/SAML / not-wired-into-establish wording explicit
- **Regression:** doc review

### WG-06 — Resolve OTP prompt duplication + `request_otp` rebuild (`P3`) — **fixed** (simplify)

- **Where:** `resolve_firebox_*` / `request_firebox_second_factor`
- **Fix:** shared `optional_firebox_second_factor`; call `request_second_factor(prompt, request)` directly (no title/subtitle rebuild)
- **Regression:** existing Null / Fake resolve tests

### WG-07 — Docs Display over-claim + default-domain pin (`P3`) — **fixed** (simplify)

- **Where:** `07-tunnels-mcp.md` redaction wording; `FIREBOX_DEFAULT_DOMAIN`
- **Evidence:** `FireboxSecondFactor` / Fake have `Debug` only (password has `Display`); default domain constant untested
- **Fix:** precise redaction wording; `firebox_default_domain_matches_csharp`; `watchguard/mod.rs` field-fork note
- **Regression:** that test + doc review

---

## Rejected candidates

| ID | Severity | Reason |
|---|---|---|
| REJ-01 | — | Wire Firebox HTTP / SAML / push web long-poll into `WatchguardProvider::establish` — explicitly out of scope |
| REJ-02 | — | Rewrite `WatchguardProvider::establish` OpenVPN spawn path — forbidden by review authority |
| REJ-03 | — | Zeroize password/OTP on `Drop` — hardening beyond C# / stub surface |
| REJ-04 | — | Constant-time `PartialEq` on `FireboxPassword` / `OtpCode` — not a logging boundary for this stub |
| REJ-05 | — | Portal empty-OTP resolve test duplicate of CRV1 (same `optional_firebox_second_factor` helper) |
| REJ-06 | — | Domain wire formatting using `FIREBOX_DEFAULT_DOMAIN` — HTTP portal not in scope; constant exported for parity |
| REJ-07 | — | CRV1 Push without `ApprovePushViaWebLogonAsync` — HTTP residual; stub only arms `"p"` challenge |

---

## Adversarial cycles

1. **Cycle 1 (findings):** WG-01 / WG-02 / WG-03 / WG-04 / WG-05 accepted → Null/empty/field-fork/password-trim/docs → reset  
2. **Clean pass 1:** Security → boundaries → contract (redaction, Null cancel, CRV1/portal fields, password spaces, docs) — no accepted findings  
3. **Clean pass 2:** Integration drift / test resistance (exports; establish untouched; Fake mutex poison; no silent field cross) — REJ-01..07 — no accepted findings  
4. **Post-simplify adversarial re-run:** 2 clean passes on `optional_firebox_second_factor` + `request_second_factor` reuse + doc/default-domain delta — no accepted findings  

---

## Iterative-review-simplify cycles

1. **Cycle 1 (fixes):** reuse (`optional_firebox_second_factor`); quality (mod docs field fork; `FIREBOX_DEFAULT_DOMAIN` pin; Display wording)  
2. **Cycle 2 (fixes):** reuse (`request_second_factor` with full `OtpPromptRequest`)  
3. **Clean pass 1:** reuse / efficiency / quality — no validated findings  
4. **Clean pass 2:** same — no findings  
5. **Clean pass 3:** same — no findings  

---

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-tunnels
```

Focused: `cargo test -p wormhole-tunnels --lib providers::watchguard::`

---

## Residual / out-of-scope notes

- `WatchguardProvider::establish` still takes already-resolved OpenVPN stdin JSON; call `resolve_firebox_*` / materials helpers when portal / cache loops land.
- **Firebox HTTP pre-auth / SAML WebView2 UI are not wired.** Shared data plane remains `tools/wormhole-ovpnproxy` (no WatchGuard-specific binary).
- CRV1 Push arms `challenge_response = "p"` only; C# web push long-poll approval remains a future HTTP port.
