# Adversarial ledger — SSH agent ↔ auth select glue

**Scope:** `rust/crates/wormhole-ssh/src/agent_auth_select.rs` (`select_auth_methods_for_connect` / `filter_ssh_auth_methods_for_connect` / `agent_auth_allowed` / `FallibleAgentProbe` / `FakeFallibleAgent`), select exports in `lib.rs`  
**Out of scope:** `agent.rs` probe implementation (closed in [adversarial-ledger-ssh-agent.md](adversarial-ledger-ssh-agent.md)); `known_hosts.rs` / host-key verify; russh agent wire auth  
**Impl:** `c012dfe1-a300-47ab-8992-33c9eeebc38b`  
**Date:** 2026-07-31  
**Authority:** full adversarial-review-fix (edit in scope)  
**Gates:** 2 clean adversarial cycles + 3 clean iterative-review-simplify cycles (adversarial renewed after simplify edits)

## Baseline

- `cargo test -p wormhole-ssh` — green (128 passed + 1 ignored before select hardening).
- `cargo test -p wormhole-ssh --no-default-features` — green (select glue always on; `filter_*` / client tests gated).

## Attack criteria (user)

| Criterion | Result |
|---|---|
| Available → keep Agent | **Held** — `select` / `filter` preserve Agent entries and order |
| Unavailable → drop Agent | **Held** — Agent filtered out; agent-only → `Ok([])` (drop, not Err) |
| Probe `Err` → fail closed | **Held** — whole select returns `AgentAuthSelectError` (even when Password also listed) |
| Skip probe if Agent not a candidate | **Held** — `include_agent_if_requested(false, …)` / CountingProbe asserts 0 calls |
| No secrets / endpoint paths in errors | **Held** — static `&'static str` messages; Debug regressions |

## Findings

| ID | Sev | Location | Issue | Disposition |
|---|---|---|---|---|
| SSH-AAS1 | P2 | `agent_auth_select` tests | Agent-only + unavailable not pinned as `Ok([])` (vs Err) | **Fixed** — `agent_only_unavailable_returns_empty_ok` + `filter_agent_only_unavailable_returns_empty_ok` |
| SSH-AAS2 | P2 | `agent_auth_select` tests | Probe call count (0 without Agent; exactly once with duplicates) unpinned | **Fixed** — `CountingProbe` + `probe_runs_exactly_once_*` / `probe_not_called_*` / filter twins |
| SSH-AAS3 | P3 | `AuthMethodKind` ↔ `SshAuthMethod` | Label / kind mapping drift risk across crates features | **Fixed** — `auth_method_kind_labels_match_ssh_auth_method` (`client`) |
| SSH-AASR1 | — | Soft-drop Agent on probe Err when Password present | Would weaken documented fail-closed whole-select | **Rejected** — criteria require fail closed on `Err` |
| SSH-AASR2 | — | `PlatformAgentProbe` never yields `Err` (blanket → `Ok`) | Platform maps unknown I/O to unavailable in `agent.rs` | **Rejected** — layered contract; select Err channel is for fallible wrappers / fakes |
| SSH-AASR3 | — | Generic unify of `select` + `filter` | Over-abstraction for two list shapes | **Rejected** — shared `include_agent_if_requested` is enough |

## Simplify deltas (after adversarial)

- Extracted private `include_agent_if_requested` shared by `select_auth_methods_for_connect` and `filter_ssh_auth_methods_for_connect`.
- Strengthened filter unavailable assertion to keep Password username/secret bytes.

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-ssh
cargo test -p wormhole-ssh --no-default-features
```

**Result (final):** default features — 143 passed + 1 ignored (live server); `--no-default-features` — 110 passed. `agent_auth_select` module: 20 unit tests with `client` / 13 without.

## Gate confirmation

- Adversarial clean passes: **2** (independent orderings; renewed after simplify helper extract).
- Iterative-review-simplify clean passes: **3**.
- No accepted non-blocked findings remain.
- `agent.rs` / `known_hosts.rs` / host-key verify untouched by this review.
