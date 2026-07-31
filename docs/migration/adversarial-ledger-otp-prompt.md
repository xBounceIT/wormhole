# Adversarial ledger — OTP / SecondFactorPrompt stub

**Scope:** `rust/crates/wormhole-tunnels/src/providers/auth_glue/otp_prompt.rs` (+ exports in `auth_glue/mod.rs` / `lib.rs`); docs `07-tunnels-mcp.md` OTP notes  
**Authority:** full adversarial-review-fix (edit in scope; do **not** wire provider portal establish loops)  
**Baseline:** `cargo test -p wormhole-tunnels` green (87+ tests) before review  
**Compared against:** C# `Services/Tunneling/IOtpPromptService.cs` (trimmed string / null dismiss; cancel ≠ exception)

---

## Gate summary

| Gate | Result |
|---|---|
| Adversarial clean passes | **2** consecutive (post-fix; re-run after simplify) |
| Iterative-review-simplify clean passes | **3** consecutive |
| `cargo test -p wormhole-tunnels` | **pass** (91 lib + 15 lease + 24 sidecar) |

---

## Accepted findings

### OTP-01 — `MemoryOtpPrompt` derived `Debug` leaked queued codes (`P1`) — **fixed**

- **Where:** `otp_prompt.rs` `MemoryOtpPrompt` / `FakeOtpPrompt`
- **Invariant:** OTP material never appears in `Debug` / logs / panic formatting of secret-bearing types
- **Evidence:** `Mutex<VecDeque<Option<String>>>` via `#[derive(Debug)]` prints `Some("secret-otp")` (confirmed with a `rustc` probe)
- **Fix:** Custom `Debug` redacts queued `Some` slots via shared `redact_nonempty`; `OtpCode` `Debug`/`Display` reuse the same helper
- **Regression:** `memory_prompt_debug_redacts_queued_codes`, `otp_code_debug_and_display_redact`, `otp_response_debug_redacts_submitted`

### OTP-02 — Empty / whitespace / dismiss contracts under-pinned (`P2`) — **fixed**

- **Where:** `request_otp` / `request_second_factor` / `NullOtpPrompt`
- **Invariant:** trim → reject empty as `TunnelError::Establish`; user dismiss / Null fail-closed → `Cancelled`; never echo whitespace in errors
- **Evidence:** whitespace-only covered; bare `""` and Null `Ok(Cancelled)` path lacked explicit regressions
- **Fix:** `request_otp_empty_string_fails`; `null_prompt_always_cancels` asserts direct `Cancelled` + hook mapping
- **Regression:** those tests + existing trim / cancel tests

### OTP-03 — Channel abandon / re-arm fail-closed under-tested (`P2`) — **fixed**

- **Where:** `ChannelOtpPrompt` + `request_otp` error map
- **Invariant:** oneshot drop / channel closed → `TunnelError::Cancelled`; `set_auto_cancel` restores Null-like fail-closed
- **Evidence:** receiver-drop returned `OtpPromptError::ChannelClosed` only at trait layer; pending drop → hook mapping missing
- **Fix:** `channel_pending_drop_maps_to_cancelled`, `channel_set_auto_cancel_fail_closed_again`
- **Regression:** those tests

### OTP-04 — Docs over-claimed `Display` redaction (`P3`) — **fixed** (simplify)

- **Where:** `docs/migration/07-tunnels-mcp.md`
- **Evidence:** claimed `Display` for `OtpPromptResponse` / `MemoryOtpPrompt` (only `OtpCode` implements `Display`)
- **Fix:** Corrected redaction wording; linked this ledger; kept “not wired into provider portal loops” explicit

### OTP-05 — Channel AutoCancel allocated unused oneshot (`P3`) — **fixed** (simplify)

- **Where:** `ChannelOtpPrompt::prompt`
- **Fix:** Create oneshot only in `Channel` mode

---

## Rejected candidates

| ID | Severity | Reason |
|---|---|---|
| REJ-01 | — | Wire portal / pre-auth loops into WatchGuard / Stormshield / Cisco / Fortinet `establish` — explicitly out of scope |
| REJ-02 | — | C# `CancellationToken` on `PromptAsync` — stub has `OtpPromptError::Cancelled`; UI host later |
| REJ-03 | — | Zeroize OTP bytes in `Drop` — hardening beyond C# / stub surface |
| REJ-04 | — | Reject ZWSP-only codes — C# `Trim()` parity (ZWSP not whitespace) |
| REJ-05 | — | Constant-time `PartialEq` on `OtpCode` — not a logging/auth boundary for this stub |
| REJ-06 | — | Shared Debug helper beyond `redact_nonempty` — over-abstract for one queue formatter |

---

## Adversarial cycles

1. **Cycle 1 (findings):** OTP-01 / OTP-02 accepted → redacted `Memory` Debug + empty/Null regressions → reset  
2. **Cycle 2 (findings):** OTP-03 accepted → channel pending-drop / auto-cancel tests → reset  
3. **Clean pass 1:** Security → boundaries → contract (redaction, trim, Null, docs wiring claims) — no accepted findings  
4. **Clean pass 2:** Integration drift / concurrency / test resistance (no `request_otp` from establish; channel await outside lock) — REJ-01..06 — no accepted findings  
5. **Post-simplify adversarial re-run:** 2 clean passes on oneshot-move + `raw`/`trimmed` + doc wording delta — no accepted findings  

---

## Iterative-review-simplify cycles

1. **Cycle 1 (fixes):** efficiency (oneshot only in Channel mode); reuse (`redact_nonempty`); quality (`raw`/`trimmed` naming)  
2. **Cycle 2 (fixes):** docs Display over-claim (OTP-04)  
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

Focused: `cargo test -p wormhole-tunnels --lib providers::auth_glue::otp_prompt::`

---

## Residual / out-of-scope notes

- Provider portal / SAML / Entra loops still construct `ResolvedOvpnMaterials` offline; `request_otp` is the hook for when those land.
- `OtpPromptError::Cancelled` remains for future token/shutdown wiring; user dismiss stays `OtpPromptResponse::Cancelled`.
