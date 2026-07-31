# Adversarial ledger — Session orch Fake SSH reconnect glue

**Scope:** `rust/crates/wormhole-session/src/ssh_reconnect.rs`
(`FakeSshReconnectGlue` / `FakeSshReconnectResult` / `apply_fake_reconnect_result`),
exports in `lib.rs`, `Cargo.toml` description, docs
`16-session-orchestrator.md` / `06-ssh-spike.md` / `feature-matrix.md` /
README ledger link; this ledger.

**Out of scope:** Live SSH dial / WebView2 rebind; mutating
`SessionOrchestrator::connect` for auto-reconnect; credential fields; GPUI;
policy internals (see [`adversarial-ledger-ssh-reconnect.md`](adversarial-ledger-ssh-reconnect.md)).

**Compared against:** C# `SshSessionViewModel` auto-reconnect
(`UnexpectedDrop` / user cancel / budget exhaustion note) +
`wormhole_ssh::reconnect` API.

**Authority:** full adversarial-review-fix (edit in scope; no child agents;
no commit/push)  
**Baseline (pre-fix):** new glue module + unit tests; policy crate green  
**Final:** `cargo test -p wormhole-session` / `cargo test -p wormhole-ssh` green
(session lib **46** unit incl. **19** `ssh_reconnect` + **34** orchestrator_fakes;
ssh reconnect module **25**).

Context7 MCP unavailable in this environment (no dependency pin changes).

---

## Gate summary

| Gate | Result |
|---|---|
| Adversarial clean passes | **2** consecutive (independent attack order; re-established after fix + simplify delta) |
| Iterative-review-simplify clean passes | **3** consecutive |
| `cargo test -p wormhole-session` | **pass** |
| `cargo test -p wormhole-ssh` | **pass** (1 ignored live SSH) |
| `git diff --check` (scoped) | **pass** |

---

## Attack criteria (user)

| Criterion | Result |
|---|---|
| UnexpectedDrop → existing `SshReconnectPolicy` | **Held** — `handle_disconnect` / `run_fake_loop` |
| UserCancel never reconnects | **Held** — Stop(`UserCancel`) + budget reset; loop consumes no outcomes |
| Budget exhausted → Failed | **Held** — `SessionState::Failed` + `reconnect_exhausted_note` |
| Fake schedule | **Held** — delays recorded, never slept |
| Prefer `wormhole-session`; reuse `wormhole-ssh::reconnect` | **Held** — thin glue only |

---

## Accepted findings and fixes

| ID | Sev | Location | Invariant / evidence | Fix | Verification |
|---|---|---|---|---|---|
| SSR-01 | P1 | `run_fake_loop` | Empty script called `begin_fake_retry` before peek → half-applied budget/delay | Peek outcome **before** `begin_fake_retry` | `script_exhausted_fail_closed`, `script_exhausted_mid_loop_preserves_prior_attempts_only` |
| SSR-02 | P2 | tests | `Connecting` → `NotTerminal` Failed unpinned | `connecting_outcome_fails_closed_as_not_terminal` | that test |
| SSR-03 | P2 | tests | `apply_fake_reconnect_result` non-budget Failed path unpinned | `apply_non_budget_failed_uses_reason_label` | that test |
| SSR-04 | P3 | `csharp_defaults` | Bypassed `new()` mismatch gate | Route through `with_fake_delays` | `csharp_defaults_use_policy_constants` |
| SSR-05 | P3 | docs | Orch loop still “Pending” in 16/matrix/06 | Document Fake glue; UI rebind still Pending | doc review |

### Simplify delta (post-adversarial)

| ID | Sev | Location | Change | Verification |
|---|---|---|---|---|
| S-01 | — | `csharp_defaults` | Shared construction via `with_fake_delays` | suite; adversarial re-looped |
| S-02 | — | `with_fake_delays` rustdoc | Clarify empty = policy disabled | doc |
| S-03 | — | tests | Avoid `PartialEq` on `SessionError` in apply asserts | compile |

Production deltas from SSR-01 / S-01 → adversarial re-looped to 2 clean.

---

## Rejected candidates

| Candidate | Reason |
|---|---|
| Wire auto-reconnect into `SessionOrchestrator::connect` | Out of scope — Fake glue only; live UI Pending |
| Map `Cancelled` → `SessionState::Failed` | C# Disconnect is not Failed; `Closed` is the closest existing state |
| Add `SessionError::ReconnectExhausted` variant | `Other` + note string matches exhaustion Display; avoid enum churn |
| Sleep Fake delays under tokio time | Deliverable: Fake schedule record-only |
| Reimplement backoff in session crate | Must reuse `wormhole_ssh::reconnect` |
| Derive `PartialEq` on `SessionError` for tests | Wider blast radius; pattern-match instead |

---

## Regression coverage (`ssh_reconnect::tests`)

- UnexpectedDrop → Retry + Fake delay record
- UserCancel never retries / resets budget / loop skips outcomes
- Budget exhausted → Failed + note + `apply_fake_reconnect_result`
- Retryable failures then Connected; mid-connect Disconnected → Cancelled
- Non-retryable / PolicyDisabled / Connecting(NotTerminal) fail closed
- Script exhausted (empty + mid-loop) without half-apply
- Hostile budget/schedule mismatch; stability reset; Debug hygiene
- csharp_defaults constants

---

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-session
cargo test -p wormhole-ssh
```

**Result (final):** both green (wormhole-ssh: 1 ignored live client test).

## Gate confirmation

- Adversarial clean passes: **2** (independent lane orderings; renewed after simplify).
- Iterative-review-simplify clean passes: **3**.
- No accepted non-blocked findings remain.
- No commit/push (per parent instruction).
