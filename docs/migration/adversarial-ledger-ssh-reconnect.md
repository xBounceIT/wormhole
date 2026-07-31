# Adversarial ledger — SSH reconnect / backoff policy stub

**Scope:** `rust/crates/wormhole-ssh/src/reconnect.rs` (`SshReconnectPolicy` / `SshReconnectBudget` / `BackoffSchedule` / `FakeBackoffSchedule` / `FixedBackoffSchedule` / decide helpers), reconnect exports in `lib.rs`, reconnect section of `docs/migration/06-ssh-spike.md`  
**Out of scope:** Live SSH reconnect loop / WebView2 rebind; credential fields; GPUI.
Session orch Fake glue: [`adversarial-ledger-session-ssh-reconnect.md`](adversarial-ledger-session-ssh-reconnect.md).
**Date:** 2026-07-31

**Authority:** full adversarial-review-fix (edit in scope)  
**Gates:** 2 clean adversarial cycles + 3 clean iterative-review-simplify cycles (adversarial renewed after simplify edits)

## Baseline

- `cargo test -p wormhole-ssh --lib reconnect` — green (18 passed before hardening).
- Stub already mirrored C# constants (3 / 10s / 30s) and `ShouldContinueAutoReconnect` (Failed+retryable only).

## Attack criteria (C# / docs)

| Criterion | Result |
|---|---|
| User cancel → never auto-reconnect | **Held** — `decide_after_disconnect` / policy Stop(`UserCancel`) |
| Unexpected drop / retryable error → bounded Retry | **Held** — `plan_next_attempt` + Fake/Fixed schedules |
| Non-retryable error → Stop | **Held** — auth / host-key / notice path |
| Continue after connect only Failed+retryable | **Held** — `should_continue_auto_reconnect` + `decide_after_connect_attempt` |
| Budget reset: stability + user cancel / manual Retry | **Held** — `on_stability_elapsed` / `cancel_user` / policy `on_disconnect(UserCancel)` |
| Hostile budget/schedule → fail closed (never Retry) | **Held** — mismatch / lying Fake / consumed>max → `ReconnectPolicyError` |
| No secrets / host in notes or Debug | **Held** — static messages; exhaustion note is count-only; Debug regressions |

## Findings

| ID | Sev | Location | Issue | Disposition |
|---|---|---|---|---|
| SSH-RC1 | P2 | `SshReconnectPolicy::on_disconnect` | `&self` UserCancel Stop left stale `attempts_consumed` (C# Disconnect clears) | **Fixed** — `&mut self`; UserCancel calls `cancel_user()` before decide |
| SSH-RC2 | P1 | `SshReconnectPolicy::begin_retry` | Stale Retry verdict recorded then Err — half-applied budget | **Fixed** — validate `attempt == consumed + 1` **before** `record_attempt` |
| SSH-RC3 | P2 | tests | Connect Failed(non-retryable) / Connecting stop reasons, exhausted `record_attempt`, stale `begin_retry` unpinned | **Fixed** — focused regressions |
| SSH-RC4 | P3 | module / helper docs | Budget “only stability” + `should_continue` “while budget remains” inaccurate | **Fixed** — module + helper docs |
| SSH-RCR1 | — | Validate every delay `1..=max` in `validate_schedule` | Spot-check attempt 1; holes → `BudgetExhausted` | **Rejected** — still fail closed; denser check adds churn |
| SSH-RCR2 | — | Merge `cancel_user` / `on_stability_elapsed` | Shared `reset` body | **Rejected** — distinct C# call-site semantics |
| SSH-RCR3 | — | Drop public `should_continue_auto_reconnect` | Unused by decide after match rewrite | **Rejected** — C# parity helper, unit-tested |
| SSH-RCR4 | — | Live loop / orch wiring | Documented Pending | **Rejected** — out of scope |

## Simplify deltas (after adversarial)

- `on_disconnect(UserCancel)` reuses `cancel_user()` instead of a second `reset` call.
- Removed unreachable post-record Err branch in `begin_retry` (`debug_assert_eq!` only).
- Clarified `SshReconnectPolicy` / `should_continue_auto_reconnect` docs.

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-ssh --lib reconnect
cargo test -p wormhole-ssh --no-default-features --lib reconnect
cargo test -p wormhole-ssh
cargo test -p wormhole-ssh --no-default-features
```

**Result (final):** default features — 168 passed + 1 ignored (live server); `--no-default-features` — 135 passed. Reconnect module: 25 unit tests (always on).

## Gate confirmation

- Adversarial clean passes: **2** (independent orderings; renewed after simplify edits).
- Iterative-review-simplify clean passes: **3**.
- No accepted non-blocked findings remain.
- Live reconnect loop / orchestrator wiring untouched (Pending).
