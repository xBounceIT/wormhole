# Adversarial ledger — Fortinet SAML prompt UI glue (`wormhole-ui`)

**Scope:** `rust/crates/wormhole-tunnels/src/providers/fortinet/saml.rs` (`ChannelSamlAuthCallback` / `PendingSamlPrompt` / `SamlPromptResponse`); `rust/crates/wormhole-ui/src/saml_prompt.rs` (`SamlPromptChannel` / `FakeSamlPromptUi` + submit/cancel helpers); `lib.rs` tunnels re-exports; docs `07-tunnels-mcp.md`, `08-ui.md`, `feature-matrix.md`, this ledger + README row  
**Authority:** full adversarial-review-fix (edit in scope)  
**Out of scope:** WebView2 / OS-browser / GPUI chrome; HardwarePass / live FortiGate; loopback listener  
**Baseline:** `cargo test -p wormhole-ui --lib saml_prompt` (13 → 19 tests); `cargo test -p wormhole-tunnels --lib providers::fortinet::saml::` (25) green; full `cargo test -p wormhole-tunnels` (340 lib + 21 lease + 24 sidecar) + `wormhole-ui --lib` (258) green  
**Compared against:** C# `FortinetSamlAuthService` transport (Submit auth_id/SVPNCOOKIE / Cancel / abandon); tunnels `ChannelSamlAuthCallback` + `authenticate` / `establish_fortinet` contracts; OTP UI glue pattern (`OtpPromptChannel`)  
**Context7 MCP:** unavailable; pins from workspace `Cargo.toml` / `deps-pins.md`  
**Impl:** d0621dcc-513f-4d7a-a6a9-09ec4b2263f5

---

## Gate summary

| Gate | Result |
|---|---|
| Adversarial clean passes | **2** consecutive (post-fix; re-run after simplify) |
| Iterative-review-simplify clean passes | **3** consecutive |
| `cargo test -p wormhole-ui --lib saml_prompt` | **pass** (19) |
| `cargo test -p wormhole-tunnels --lib providers::fortinet::saml::` | **pass** (25) |
| `cargo test -p wormhole-tunnels` / `wormhole-ui --lib` | **pass** (340 lib + 21 lease + 24 sidecar; UI 258) |

---

## Accepted findings

### SAML-UI-01 — Fail-closed / empty contracts under-pinned (`P2`) — **fixed**

- **Where:** `saml_prompt.rs` tests + module docs
- **Invariant:** Cancel / Fake `None` / exhausted script / pending or channel abandon → `Cancelled` / `ChannelClosed` (establish → `TunnelError::Cancelled`); Submitted empty / whitespace / wrong kind → `InvalidResult` (never echo tokens). External+realm rejected before prompt.
- **Evidence:** Whitespace + cancel + realm covered; bare `""`, multi-step Fake, abandon→establish `Cancelled`, submit-after-abort, wrong-kind via Fake UI, and join-pattern pin lacked regressions
- **Fix:** Focused tests + module wording clarifying InvalidResult vs Cancelled/ChannelClosed
- **Regression:** `empty_string_submit_is_invalid_result_not_cancelled`, `fake_ui_multi_step_submit_then_cancel`, `submit_helpers_false_when_provider_abandoned`, `establish_pending_drop_maps_to_cancelled`, `wrong_kind_via_fake_ui_fails_without_echo`, `shared_plus_pending_rx_is_the_join_pattern`

### SAML-UI-02 — Docs / ledger index drift (`P3`) — **fixed**

- **Where:** `08-ui.md`, `07-tunnels-mcp.md`, `feature-matrix.md`, `README.md`
- **Evidence:** UI glue existed but SAML prompt row / ledger link / Fortinet matrix spike wording were missing
- **Fix:** Doc rows + ledger link; this file

### SAML-UI-S1 — Module docs named internal `authenticate` (`P3`) — **fixed** (simplify)

- **Where:** `saml_prompt.rs` module docs
- **Fix:** Point at public `authenticate_fortinet_saml`

### SAML-UI-S2 — Establish-path UI test boilerplate (`P3`) — **fixed** (simplify)

- **Where:** `saml_prompt.rs` tests
- **Fix:** Shared `forti_fixture` helper; cancel test uses `push_cancel`

---

## Rejected candidates

| ID | Severity | Reason |
|---|---|---|
| REJ-01 | — | WebView2 / OS-browser / GPUI chrome — explicitly out of scope |
| REJ-02 | — | HardwarePass / live FortiGate — forbidden by review request |
| REJ-03 | — | Share `redact_nonempty` from tunnels into UI Fake Debug — private helper; `[REDACTED]` string parity is enough |
| REJ-04 | — | Zeroize tokens on Drop — hardening beyond stub / C# surface |
| REJ-05 | — | Merge `FakeSamlPromptUi` with tunnels `FakeSamlAuthCallback` — different sides of the channel |
| REJ-06 | — | `answer_next` treat failed oneshot send as `Err` — Fake counts an answered attempt; provider already fail-closed |
| REJ-07 | — | Avoid double-clone of non-secret `SamlAuthRequest` in `answer_next` — matches OTP glue; micro-opt |
| REJ-08 | — | Re-export `establish_fortinet` from `wormhole-ui` — OTP also keeps establish on tunnels; glue re-exports auth hook + channel types |
| REJ-09 | — | Map authenticate-level `ChannelClosed` to `Cancelled` in UI helpers — establish already maps; raw authenticate parity with tunnels is correct |
| REJ-10 | — | Embedded+pin before-prompt UI regression — covered in tunnels establish; user gate called out external+realm |

---

## Adversarial cycles

1. **Cycle 1 (findings):** SAML-UI-01 / SAML-UI-02 accepted → regression tests + docs/ledger index → reset  
2. **Clean pass 1:** Security → boundaries → contract (redaction, empty vs Cancelled, abandon→establish Cancelled, realm preflight) — no accepted findings  
3. **Clean pass 2:** Integration drift / concurrency / test resistance (re-exports, join pattern, multi-step Fake, mutex released before await) — REJ-01…10 — no accepted findings  
4. **Post-simplify adversarial re-run:** 2 clean passes on `forti_fixture` + module-doc delta — no accepted findings  

---

## Iterative-review-simplify cycles

1. **Cycle 1 (fixes):** quality — module docs name `authenticate_fortinet_saml` (SAML-UI-S1); reuse — `forti_fixture` + `push_cancel` consistency (SAML-UI-S2)  
2. **Clean pass 1:** reuse / efficiency / quality — no validated findings (reject shared redact helper, micro-opt clone, cross-crate Fake merge)  
3. **Clean pass 2:** same — no findings  
4. **Clean pass 3:** same — no findings  

---

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-ui --lib saml_prompt
cargo test -p wormhole-tunnels --lib providers::fortinet::saml::
cargo test -p wormhole-tunnels
cargo test -p wormhole-ui --lib
```

Result: **pass** — UI saml_prompt **19** ok; tunnels saml **25** ok; tunnels package **340** lib + **21** lease + **24** sidecar; `wormhole-ui --lib` **258** ok.

---

## Residual / out-of-scope notes

- WebView2 / external-browser / loopback listener remain TODO; this module is transport + Fake only.
- `StubSamlAuthCallback` remains a production default until a real host drains `SamlPromptChannel`.
- Pre-existing `wormhole-ui` warning: unused `format_http_address` / `parse_http_address` in `connection_editor` (unrelated).
