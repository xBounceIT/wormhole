# Adversarial ledger — MCP tool approval gate Fake glue

**Scope:** `rust/crates/wormhole-mcp/src/approval.rs` (+ crate-root re-exports in
`lib.rs` / `Cargo.toml` description); `canonicalize_session_id` pub for shared
id validation; rustdoc cross-refs in `capability.rs` / `session_registry.rs`;
docs `07-tunnels-mcp.md` (status + Approval gate Fake glue row + tests /
non-goals), `feature-matrix.md` (MCP tools row), `README.md` ledger index;
this ledger.

**Out of scope:** Streamable HTTP `dispatch_tool` wiring to the Fake glue;
live SSH / russh / tool execution; GPUI / WinUI approval dialog; C#
`Services/Mcp` mutations; bearer mint / CredMgr; contested crates
(`wormhole-ssh`, `wormhole-ui`, `wormhole-session`).

**Compared against:** C# `EnsureMcpApprovedAsync` / `ResolveApprovedAsync`
(Connected-only id lookup, per-session consent, Deny fail-closed,
agent-readable errors). Lab adds explicit **Cancel** (dismiss) and
`FakeMcpToolApprovalGlue` / `FakeMcpApprovalUi` in front of fail-closed
`execute_tool`.

**Authority:** full adversarial-review-fix (edit in scope; no child agents)  
**Baseline:** `cargo test -p wormhole-mcp` green (44 lib + 19 integration)
before approval-gate Fake expansion  
**Final:** 58 lib + 19 integration green; `--no-default-features` check green  

**Attack focus:** blank / padded / control-char session ids; unknown /
non-session tools; Deny vs Cancel vs channel-closed vs dropped oneshot;
Connected eligibility only when registry present; AutoDeny default;
exhausted Fake UI → Cancel; Debug / errors never carry bearer/token;
execute_tool still unwired after Approve; no live MCP/SSH I/O.

Context7 MCP unavailable in this environment.

---

## Gate summary

| Gate | Result |
|---|---|
| Adversarial clean passes | **2** consecutive (independent attack order; re-run after simplify — no code delta) |
| Iterative-review-simplify clean passes | **3** consecutive |
| `cargo test -p wormhole-mcp` | **pass** (58 unit + 19 integration) |
| `cargo check -p wormhole-mcp --no-default-features` | **pass** |
| `git diff --check` (scoped) | **pass** (CRLF warnings only) |

---

## Accepted findings and fixes

| ID | Sev | Location | Invariant / evidence | Fix | Verification |
|---|---|---|---|---|---|
| MAG-01 | P2 | `SessionApprovalGate::mark_approved` | Padded ids could land in the approval cache (`"  s1  "` vs `"s1"`), so later `is_approved` / `ensure_approved` disagreed | Canonicalize inside `mark_approved`; ignore blank / control-char | `padded_session_id_canonicalized_for_cache` |
| MAG-02 | P2 | `ensure_approved` / glue | Blank / control-char session ids and non-session tools (`list_sessions`, empty, control chars) could reach the channel or pollute AutoApprove cache | Canonicalize session id + restrict tools to `run_command` / `send_text` / `read_terminal` before channel | `blank_and_control_session_id_rejected_before_channel`, `blank_and_unknown_tool_rejected` |
| MAG-03 | P2 | `ApprovalDecision` / Fake UI | Cancel / dismiss was missing (only Approve/Deny); exhausted scripts needed fail-closed dismiss parity with SAML Fake `None` | Add `Cancel`; `FakeMcpApprovalUi` exhausted → Cancel; distinct cancelled error copy | `channel_approve_deny_cancel`, `fake_ui_script_and_exhausted_cancels` |
| MAG-04 | P3 | docs / rustdoc | Status / matrix / non-goals lagged Approve/Deny/Cancel glue + Connected eligibility | Update `07-tunnels-mcp.md`, feature-matrix, README ledger; capability / registry rustdoc cross-refs | doc review + tests green |

---

## Rejected candidates

| Candidate | Reason |
|---|---|
| Coalesce concurrent `ensure_approved` for the same session (C# shares in-flight task) | Lab Fake; production UI coalescing can land with the real dialog; channel tests stay deterministic without shared in-flight state |
| Wire `FakeMcpToolApprovalGlue` into `WormholeMcpHandler::dispatch_tool` | Explicit non-goal (HTTP dispatch / live SSH still unwired); handler keeps thin `SessionApprovalGate` stub |
| Require registry always present | Spec: eligibility only **if** `session_registry` present |
| Case-fold tool / session ids | MCP tool names and C# `McpId` compare are ordinal / case-sensitive |
| Return `Ok(())` from glue `execute_tool` after Approve | Live exec must stay fail-closed; distinct not-wired message |
| Put Cancel-only Fake UI in `wormhole-ui` | Prefer `wormhole-mcp`; no GPUI chrome this milestone |
| Mutate C# `Services/Mcp` | Out of scope |
| Bound approval cache size (DoS) | In-memory Lab Fake only; not a network surface |

---

## Adversarial clean passes (2 required)

### Clean pass 1 — order: contract → boundary → state → concurrency → security

- Approve / Deny / Cancel + AutoDeny default; Deny/Cancel/channel-closed/dropped fail-closed.
- Blank / padded / control-char ids; unknown / `list_sessions` tools rejected before channel.
- Approval cache uses canonical ids; clear + re-prompt works.
- Mutex poison recover; oneshot drop → dropped error; no SSH I/O.
- Debug / errors omit bearer/token/password wording; execute_tool not wired after Approve.
- Registry present → Connected-only eligibility before channel; absent → approval only.
- **Accepted findings:** none (MAG-01..04 already fixed).

### Clean pass 2 — order: test resistance → integration drift → boundaries → operability → security

- Unit suite pins Approve/Deny/Cancel, Fake UI Deny + exhausted Cancel, channel closed, registry missing/Connected, Debug redaction.
- Trait/HTTP handler untouched; Fake glue optional registry; `--no-default-features` compiles approval helpers.
- Docs/matrix/ledger aligned with “Fake yes / live dispatch no”.
- **Accepted findings:** none.

`adversarial_clean_passes = 2`.

---

## Iterative-review-simplify (3 clean cycles)

Each cycle: Code Reuse → Code Efficiency → Code Quality and Bugs (+ simplify discipline).

| Cycle | Themes | Outcome |
|---|---|---|
| 1 | Reuse (`canonicalize_session_id` shared); deny/cancel helpers; no second id validator | Clean — no validated churn |
| 2 | Gate vs glue boundary; Fake UI script_len Debug; tool allow-list keeps `list_sessions` out | Clean |
| 3 | Test matrix vs attack list; feature gating; docs parity | Clean |

`simplify_clean_passes = 3`. No simplify implementation delta → adversarial remains at 2 clean.

---

## Regression tests added/updated

**`src/approval.rs` unit**
- AutoDeny fail-closed; blank / control session id; blank / unknown / control tool
- Channel Approve / Deny / Cancel + helpers; cached approval skip
- Fake UI Approve → Deny → exhausted Cancel
- Channel closed when receiver dropped; oneshot drop → dropped
- Glue without registry: deny then auto-approve → not wired
- Glue with registry: unknown / Connected / unregister fail-closed
- Glue Cancel with shared registry before execute
- Registry present rejects before channel even with open channel
- Padded id cache + `mark_approved` canonicalize
- Debug omits bearer/token/password wording

**Docs**
- `07-tunnels-mcp.md` status + Approval gate Fake glue row + tests / non-goals
- `feature-matrix.md` MCP tools row
- `README.md` ledger index

---

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-mcp
cargo check -p wormhole-mcp --no-default-features
```

**Result:** 58 unit + 19 integration pass; `--no-default-features` check pass.
