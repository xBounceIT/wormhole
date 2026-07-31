# Adversarial ledger — OTP prompt UI glue (`wormhole-ui`)

**Scope:** `rust/crates/wormhole-ui/src/otp_prompt.rs` (+ `tunnels` exports in `lib.rs` / `Cargo.toml`); docs `07-tunnels-mcp.md`, `08-ui.md`, `feature-matrix.md`, this ledger + README row  
**Authority:** full adversarial-review-fix (edit in scope)  
**Out of scope:** GPUI / ContentDialog chrome; live VPN / portal establish loops; TLS trust prompts  
**Baseline:** `cargo test -p wormhole-ui --lib otp_prompt` (8 → 13 tests); `cargo test -p wormhole-tunnels --lib providers::auth_glue::otp_prompt::` (14) green  
**Compared against:** C# `DialogOtpPromptService` transport (Submit / Cancel / null dismiss); tunnels `ChannelOtpPrompt` + `request_otp` contracts  
**Context7 MCP:** unavailable; pins from workspace `Cargo.toml` / `deps-pins.md`

---

## Gate summary

| Gate | Result |
|---|---|
| Adversarial clean passes | **2** consecutive (post-fix; re-run after simplify) |
| Iterative-review-simplify clean passes | **3** consecutive |
| `cargo test -p wormhole-ui --lib otp_prompt` | **pass** (13) |
| `cargo test -p wormhole-tunnels --lib providers::auth_glue::otp_prompt::` | **pass** (14) |

---

## Accepted findings

### OTP-UI-01 — Fail-closed / empty contracts under-pinned (`P2`) — **fixed**

- **Where:** `otp_prompt.rs` tests + module docs
- **Invariant:** Cancel / Fake `None` / exhausted script / pending or channel abandon → `TunnelError::Cancelled`; Submitted empty / whitespace → `TunnelError::Establish` (never echo code). Distinct from C# dialog (Primary disabled on whitespace).
- **Evidence:** Only whitespace + cancel paths covered; bare `""`, drop `pending_rx`, multi-step Fake, and `submit_pending` after provider abort lacked regressions
- **Fix:** Focused tests + module / 07 / 08 wording clarifying Establish vs Cancelled
- **Regression:** `empty_string_submit_is_establish_not_cancelled`, `drop_pending_rx_maps_to_cancelled`, `fake_ui_multi_step_submit_then_cancel`, `submit_pending_false_when_provider_abandoned`

### OTP-UI-02 — `&self` convenience helpers conflicted with `&mut` pending drain (`P2`) — **fixed**

- **Where:** `OtpPromptChannel::request_otp` / `request_second_factor` (removed)
- **Invariant:** Join pattern is `shared()` + spawn/`request_otp`, answer via `pending_rx` / `FakeOtpPromptUi`
- **Evidence:** Holding `&self` for async request while `pending_rx(&mut self)` is required cannot compile as a concurrent join; helpers were misleading dead weight after tunnels hooks exist
- **Fix:** Remove channel async helpers; pin `shared_plus_pending_rx_is_the_join_pattern`; docs describe the join pattern
- **Regression:** that test + existing Fake / helper tests

### OTP-UI-03 — Public glue surface incomplete (`P2`) — **fixed**

- **Where:** `wormhole-ui` `lib.rs` `tunnels` re-exports
- **Invariant:** Callers of `submit_pending` / `FakeOtpPromptUi::answer_next` need `PendingOtpPrompt`, `OtpPromptRequest`, `OtpPromptError`, hooks, etc. without a second crate import for the glue path
- **Evidence:** Public fn signatures used tunnels types that were not re-exported
- **Fix:** Re-export `request_otp` / `request_second_factor`, `ChannelOtpPrompt`, `OtpCode`, prompt request/response/error, `PendingOtpPrompt`, `SharedOtpPrompt`, `TunnelError` under feature `tunnels`

### OTP-UI-04 — Docs / ledger index drift (`P3`) — **fixed**

- **Where:** `07-tunnels-mcp.md`, `08-ui.md`, `feature-matrix.md`, `README.md`
- **Evidence:** UI glue existed but empty-vs-cancel map, join pattern, and `adversarial-ledger-otp-ui.md` were missing from the index
- **Fix:** Doc rows + ledger link; this file

---

## Rejected candidates

| ID | Severity | Reason |
|---|---|---|
| REJ-01 | — | GPUI / ContentDialog chrome / `ContentDialogGate` — explicitly out of scope |
| REJ-02 | — | Wire portal loops / live VPN — out of scope |
| REJ-03 | — | Share `redact_nonempty` from tunnels into UI Fake Debug — private helper; `[REDACTED]` string parity is enough |
| REJ-04 | — | C# `MaxLength = 32` on TextBox — dialog chrome, not transport glue |
| REJ-05 | — | Zeroize OTP on Drop — hardening beyond stub / C# surface |
| REJ-06 | — | Merge `FakeOtpPromptUi` with tunnels `MemoryOtpPrompt` — different sides of the channel |
| REJ-07 | — | `answer_next` treat failed oneshot send as `Err` — Fake counts an answered attempt; provider already fail-closed |

---

## Adversarial cycles

1. **Cycle 1 (findings):** OTP-UI-01…04 accepted → tests + remove conflicting helpers + re-exports + docs → reset  
2. **Clean pass 1:** Security → boundaries → contract (redaction, empty vs Cancelled, abandon) — no accepted findings  
3. **Clean pass 2:** Integration drift / concurrency / test resistance (join pattern, multi-step Fake, re-exports) — REJ-01…07 — no accepted findings  
4. **Post-simplify adversarial re-run:** 2 clean passes on re-export delta + inlined multi-step test — no accepted findings  

---

## Iterative-review-simplify cycles

1. **Cycle 1 (fixes):** quality — drop unusable `&self` helpers (OTP-UI-02); reuse — re-export glue types/hooks (OTP-UI-03); inline one-off test helper  
2. **Clean pass 1:** reuse / efficiency / quality — no validated findings (reject shared redact helper, micro-opt clone)  
3. **Clean pass 2:** same — no findings  
4. **Clean pass 3:** same — no findings  

---

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-ui --lib otp_prompt
cargo test -p wormhole-ui otp
cargo test -p wormhole-tunnels --lib providers::auth_glue::otp_prompt::
```

Result: **pass** — UI otp_prompt **13** ok; tunnels otp_prompt **14** ok. (`cargo check -p wormhole-tunnels` also green.)

---

## Residual / out-of-scope notes

- GPUI ContentDialog (or equivalent) remains TODO; this module is transport + Fake only.
- Provider portal / SAML / Entra loops still construct resolved materials offline except Cisco `prepare` Prompt path (tunnels stub).
