# Adversarial ledger — TLS trust prompt Fake glue

**Scope:** `rust/crates/wormhole-tunnels/src/providers/auth_glue/tls_trust_prompt.rs`
(+ exports in `auth_glue/mod.rs` / `lib.rs`); UI glue
`rust/crates/wormhole-ui/src/tls_trust_prompt.rs` + crate-root re-exports;
docs `07-tunnels-mcp.md`, `feature-matrix.md`, README ledger index; this ledger.

**Out of scope:** WinUI / GPUI ContentDialog; Stormshield portal TLS consent loop
(`ConfirmTrustAsync` / persist `TrustServerCertificate`); live TLS handshake /
certificate validation.

**Compared against:** C# `ITlsTrustPromptService` / `DialogTlsTrustPromptService`
(`AcceptButtonLabel` = `"Trust and connect"`; explicit accept → `true`; decline /
Cancel → `false`; token cancel → `OperationCanceledException` only).

**Authority:** full adversarial-review-fix (edit in scope; no child agents)  
**Baseline:** `cargo test -p wormhole-tunnels` green before TLS trust module  
**Final:** tunnels lib **367** unit + lease + sidecar green; `cargo test -p wormhole-ui --lib` **338** green  

**Attack focus:** AcceptOnce vs Reject/Cancel fail-closed; exhausted Fake script /
Null / channel abandon; fingerprint prefix Debug (never full thumbprint in logs);
tracing lengths only; channel pending drop; `ACCEPT_BUTTON_LABEL` C# parity.

Context7 MCP unavailable in this environment.

---

## Gate summary

| Gate | Result |
|---|---|
| Adversarial clean passes | **2** consecutive (independent attack order; re-run after simplify — tracing fix only) |
| Iterative-review-simplify clean passes | **3** consecutive |
| `cargo test -p wormhole-tunnels` | **pass** (367 lib + 15 lease + 24 sidecar) |
| `cargo test -p wormhole-ui --lib` | **pass** (338) |
| `git diff --check` (scoped) | **pass** |

---

## Accepted findings and fixes

| ID | Sev | Location | Invariant / evidence | Fix | Verification |
|---|---|---|---|---|---|
| TLS-01 | P1 | `request_tls_trust` tracing | Never log tunnel title / full thumbprint — lengths + 8-char prefix only | `title_len` + `fingerprint_prefix` in `tracing::debug!` | compile + request debug tests |
| TLS-02 | P2 | `request_tls_trust` / Null | Reject / dismiss must fail-closed (`TunnelError::Cancelled`) | `Rejected` → `Cancelled`; `NullTlsTrustPrompt` always reject | `request_tls_trust_reject_fail_closed`, `null_prompt_always_rejects` |
| TLS-03 | P2 | `ChannelTlsTrustPrompt` | Pending / receiver drop → cancelled at hook layer | Map oneshot drop + `ChannelClosed` → `Cancelled` | `channel_pending_drop_maps_to_cancelled`, UI `pending_drop_maps_to_cancelled` |
| TLS-04 | P2 | `TlsTrustPromptRequest` Debug | Full thumbprint / message must not appear in Debug | `title_len`, `message_len`, `fingerprint_prefix` (max 8) | `request_debug_uses_lengths_and_fingerprint_prefix` |
| TLS-05 | P3 | `FakeTlsTrustPromptUi` Debug | `last_request` must not leak full thumbprint / message | Reuses `TlsTrustPromptRequest` Debug | `request_debug_in_last_request_uses_prefix_only` |
| TLS-06 | P3 | exhausted Fake script | Empty queue → Reject (fail-closed), not accept | `pop_front` `None` → `Rejected` | `memory_prompt_accept_then_reject`, UI exhausted tests |
| TLS-07 | P3 | docs / matrix | TLS trust still "UI Pending" only for OTP | Update 07 / matrix / README | doc review |

### Simplify delta (post-adversarial)

| ID | Sev | Location | Change | Verification |
|---|---|---|---|---|
| S-01 | — | `FakeTlsTrustPromptUi::from_choices` | `mut ui` builder (matches OTP glue) | compile |
| S-02 | — | UI exports | `accept_tls_trust_pending` / `reject_tls_trust_pending` aliases avoid OTP name clash | ui lib tests |
| S-03 | — | `ACCEPT_BUTTON_LABEL` | Single const shared with C# copy | `accept_button_label_matches_csharp` |

Production deltas from TLS-01–TLS-03 → adversarial re-looped to 2 clean.

---

## Rejected candidates

| Candidate | Reason |
|---|---|
| Wire `request_tls_trust` into Stormshield portal establish | Explicit non-goal this milestone |
| GPUI / WinUI ContentDialog + `ContentDialogGate` | Out of scope — Fake / Channel transport only |
| Map user Reject to `Ok(false)` at hook | Fail-closed `Cancelled` matches OTP dismiss + provider abort semantics |
| Log full thumbprint for operator copy parity | User rule: prefix only in Debug/tracing; full value stays in `message` for future UI |
| `CancellationToken` on trait method | Stub defers token cancel to future UI host (OTP stub same) |
| Zeroize thumbprint strings in `Drop` | Hardening beyond C# / Lab surface |
| Duplicate TLS glue only in `wormhole-ui` | Core trait + hook belong in `wormhole-tunnels` auth_glue |

---

## Adversarial clean passes (2 required)

### Clean pass 1 — order: contract → boundary → security → concurrency

- AcceptOnce → `Ok(true)`; Reject / Null / exhausted / channel abandon → `Cancelled`.
- `ACCEPT_BUTTON_LABEL` matches C# `"Trust and connect"`.
- Debug / tracing: lengths + fingerprint prefix only; no full thumbprint in tests' `format!("{req:?}")`.
- Channel oneshot drop + `set_auto_reject` re-arm fail-closed.

### Clean pass 2 — order: security → concurrency → integration → contract

- Re-ran with swapped order; `MemoryTlsTrustPrompt` stores requests with safe `Debug` only.
- `StormshieldAuthGlue` export preserved in `lib.rs` after tls exports added.
- No live TLS / GPUI wiring claims in docs.

---

## Iterative-review-simplify clean passes (3 required)

1. Post TLS-01–TLS-03 fixes: tracing + reject/cancel/channel tests — suite green.
2. S-01 / S-02 / S-03 naming + const test — no behavior change.
3. Doc-only delta (ledger / matrix / 07 / README) — third clean simplify.

---

## Test command

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-tunnels --lib providers::auth_glue::tls_trust_prompt::
cargo test -p wormhole-ui --lib tls_trust_prompt
cargo test -p wormhole-tunnels
cargo test -p wormhole-ui --lib
```

**Counts:** `tls_trust_prompt` module **12** tunnels + **9** ui unit tests; full tunnels lib **367**;
wormhole-ui lib **338**.
