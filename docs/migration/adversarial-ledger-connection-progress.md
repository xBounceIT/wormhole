# Adversarial ledger — Session connecting progress stepper Fake glue

**Scope:** `rust/crates/wormhole-session/src/connection_progress.rs`
(`ConnectionProgress` / `ConnectProgressPlan` / `FakeConnectionProgressGlue` /
`describe_tunnel_phase` / `TunnelProgressReport`), exports in `lib.rs`,
`Cargo.toml` description, docs `16-session-orchestrator.md` / `feature-matrix.md` /
README ledger link; this ledger.

**Out of scope:** WinUI / GPUI overlay binding; wiring into
`SessionOrchestrator::connect`; live tunnel `IProgress` callbacks; credential
fields on steps; orchestrator cancel → `SessionState::Failed` (orch already
owns that — this glue mirrors overlay state only).

**Compared against:** C# `ConnectionProgress` / `ConnectionProgressView` /
`ConnectionPhase` (Tunnel + Connect) + `DescribeTunnelPhase(TunnelProgress)`;
Rust lab adds Resolve / Auth phases for orchestrator parity.

**Authority:** full adversarial-review-fix (edit in scope; no child agents;
no commit/push)  
**Baseline (pre-fix):** new glue module + unit tests  
**Final:** `cargo test -p wormhole-session` green (lib **85** unit incl. **21**
`connection_progress` + **34** `orchestrator_fakes`).

Context7 MCP unavailable in this environment (no dependency pin changes).

---

## Gate summary

| Gate | Result |
|---|---|
| Adversarial clean passes | **2** consecutive (independent attack order; re-established after fix + simplify delta) |
| Iterative-review-simplify clean passes | **3** consecutive |
| `cargo test -p wormhole-session` | **pass** (85 lib + 34 integration) |
| `git diff --check` (scoped) | **pass** |

---

## Attack criteria (user)

| Criterion | Result |
|---|---|
| Steps Resolve / Tunnel / Auth / Connect (lab) | **Held** — `ConnectProgressPlan` + `orchestrator_*` presets |
| Fake advances steps | **Held** — `run_fake_connect` walks scripted outcomes |
| Cancel mid-flight fail-closed | **Held** — `Cancelled` + `reset`; never `Connected` / `has_failed_step` |
| No secrets on Debug | **Held** — `detail_len` only; `TunnelProgressReport` redacted |
| Prefer `wormhole-session`; pure Rust Fake | **Held** — no GPUI |

---

## Accepted findings and fixes

| ID | Sev | Location | Invariant / evidence | Fix | Verification |
|---|---|---|---|---|---|
| CP-01 | P1 | `TunnelProgressReport` | `#[derive(Debug)]` leaked provider `detail` (gateway / OTP text) | Hand `Debug` with `detail_len` only | `tunnel_progress_report_debug_redacts_detail` |
| CP-02 | P2 | `run_fake_connect` | Script length mismatch could leave stale steps from a prior walk | Return `Err` **before** `initialize` | `script_mismatch_leaves_progress_uninitialized` |
| CP-03 | P2 | tests | `Fail()` when no active step (post-connect drop) unpinned | `fail_without_active_step_is_noop` | that test |
| CP-04 | P2 | tests | Auth-phase failure path unpinned | `auth_failure_pins_auth_phase` | that test |
| CP-05 | P3 | docs | Stepper glue missing from 16/matrix/README | Doc bullets + matrix row + ledger + README row | doc review |

### Simplify delta (post-adversarial)

| ID | Sev | Location | Change | Verification |
|---|---|---|---|---|
| S-01 | — | `ConnectionStep` predicates | `is_*` take `&self` (test `all(\|s\| s.is_completed())`) | compile + suite |
| S-02 | — | tests | Remove duplicate script-mismatch test; rename serial plan test | suite |
| S-03 | — | `run_fake_connect` loop | Drop redundant per-step manual `Completed` (next `begin` handles) | `fake_connect_success_completes_all_steps` |

Production deltas from CP-01 / S-01 → adversarial re-looped to 2 clean.

---

## Rejected candidates

| Candidate | Reason |
|---|---|
| Wire progress into `SessionOrchestrator::connect` | Out of scope — overlay Fake glue only; orch cancel semantics already tested in `orchestrator_fakes` |
| Map cancel to `Fail()` + `has_failed_step` | C# `HandleCancellationAsync` calls `Progress.Reset()`, not `Fail()` |
| Add GPUI stepper view in `wormhole-ui` | Explicit non-goal (LabOnly Fake state) |
| Require `tunnel_reports.len()` == tunnel steps | Host may omit reports; optional slice is sufficient for Fake walks |
| Redact static step `label` on Debug | Labels are fixed English ("VPN tunnel"); not host-derived |
| Expand C# `ConnectionPhase` enum in production | Rust lab only; `csharp_tunneled` / `csharp_direct` preserve C# step lists |

---

## Regression coverage (`connection_progress::tests`)

- Plan numbering / `is_last`; C# direct inactive spinner; orchestrator presets
- `begin` unknown phase no-op; prior completed + detail cleared
- `fail` active-only + `has_failed_step`; `complete_all`; `reset`
- `describe_tunnel_phase` default + provider override
- Fake walk: success → all completed; tunnel/auth failure pins phase
- Cancel before begin / after begin → reset without failed step
- Script mismatch fail-closed without initialize
- Empty plan connected when not cancelled
- Debug hygiene (`ConnectionProgress`, `TunnelProgressReport`, glue)

---

## Adversarial clean passes (2 required)

Reset after each fix batch and after simplify deltas that touched implementation.

### Clean pass 1 — order: security → concurrency → state → contract → tests

- `ConnectionProgress` / `TunnelProgressReport` Debug: lengths + phases only.
- Cancel checked before each phase and after `begin` (mid-flight).
- Script mismatch returns before mutating steps.
- `begin` guard prevents silent all-green bar.
- **Accepted findings:** none.

### Clean pass 2 — order: integration → boundaries → test resistance → operability

- `lib.rs` re-exports; 16/matrix/README parity.
- Auth/tunnel failure, no-active `fail`, empty plan, C# presets.
- No password/host substrings in Debug pins.
- **Accepted findings:** none.

`adversarial_clean_passes = 2` (re-established after S-01).

---

## Iterative-review-simplify (3 clean cycles)

| Cycle | Themes | Outcome |
|---|---|---|
| 1 (fix) | Quality (`is_*` receivers; loop completion) | S-01 / S-03 applied → adversarial re-looped |
| 1 (clean) | Reuse (mirror C# API surface); reject orch wiring | Clean |
| 2 | Reject GPUI / Fail-on-cancel / label redaction | Clean |
| 3 | Docs/matrix; dedupe tests (S-02) | Clean |

`simplify_clean_passes = 3`.

---

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-session
```

**Result (final):** green (85 lib unit + 34 `orchestrator_fakes` integration).

## Gate confirmation

- Adversarial clean passes: **2** (independent lane orderings; renewed after simplify).
- Iterative-review-simplify clean passes: **3**.
- No accepted non-blocked findings remain.
- No commit/push (per parent instruction).
