# Adversarial ledger — tunnel route prompt Fake glue

**Scope:** `rust/crates/wormhole-session/src/tunnel_route_prompt.rs` (+ exports in
`lib.rs` / `Cargo.toml`); thin settings mapper
`rust/crates/wormhole-ui/src/tunnel_route_prompt.rs` + crate-root re-exports;
docs `07-tunnels-mcp.md` (status + route-prompt row), `16-session-orchestrator.md`,
`feature-matrix.md`, README ledger index; this ledger.

**Out of scope:** WinUI / GPUI ContentDialog; wiring
`SessionOrchestrator::connect` / tree Open / Quick Connect to call
`resolve_tunnel_route` before tunnel establish; live
`TunnelConfigRepository` async lookup; C# `TunnelRoutePrompter.cs` mutations.

**Compared against:** C# `TunnelRoutePrompter` / `PromptBeforeTunnelConnect`
(setting off → no prompt; tunnel off → no prompt; Direct forces
`TunnelEnabled=false` for attempt; Cancel → abort connect; cosmetic tunnel name
lookup failures → generic label; cancel during lookup / after prompt → cooperative
abort).

**Authority:** full adversarial-review-fix (edit in scope; no child agents)  
**Baseline:** `cargo test -p wormhole-session` green before route-prompt module  
**Final:** session lib **85** unit + orchestrator_fakes **34** integration green;
`cargo test -p wormhole-ui --lib` **315** green  

**Attack focus:** setting off / tunnel off fast paths; AllowTunnel / PreferDirect /
Cancel mapping; Cancel + missing prompt + exhausted Fake script fail-closed;
lookup error → fallback label (never blocks); lookup / pre-prompt / post-prompt
cancel; PreferDirect keeps `tunnel_config_id`; Debug lengths/ids only (no names /
credentials in Fake Debug).

Context7 MCP unavailable in this environment.

---

## Gate summary

| Gate | Result |
|---|---|
| Adversarial clean passes | **2** consecutive (independent attack order; re-run after simplify — no code delta) |
| Iterative-review-simplify clean passes | **3** consecutive |
| `cargo test -p wormhole-session` | **pass** (85 lib + 34 orchestrator_fakes) |
| `cargo test -p wormhole-ui --lib` | **pass** (315) |
| `git diff --check` (scoped) | **pass** |

---

## Accepted findings and fixes

| ID | Sev | Location | Invariant / evidence | Fix | Verification |
|---|---|---|---|---|---|
| TRP-01 | P1 | `FakeTunnelRoutePromptUi` trait adapter | Unsafe `&mut` trait shim for Fake UI | `Mutex` interior mutability; `TunnelRoutePrompt` on `&self` | compile + prompt tests |
| TRP-02 | P2 | `resolve_tunnel_label` | Lookup `Err(Other)` must not block prompt (C# catches repo exceptions) | Swallow non-cancel lookup errors → `FALLBACK_TUNNEL_NAME` | `lookup_error_still_prompts_with_generic_name` |
| TRP-03 | P2 | `resolve_tunnel_route` post-prompt | Disconnect after dialog must not return profile on AllowTunnel | Re-check `cancel` after prompt before apply | `post_prompt_cancel_returns_cancelled_not_profile` |
| TRP-04 | P2 | `resolve_tunnel_route` | Prompt required but `prompt: None` must not connect | Fail-closed `Ok(None)` | `missing_prompt_when_required_fail_closed` |
| TRP-05 | P3 | `TunnelRoutePromptRequest` Debug | Connection / tunnel names must not appear in Debug | Length fields + config id only | `request_debug_uses_lengths_not_names` |
| TRP-06 | P3 | blank tunnel name lookup | Whitespace-only configured name → fallback | `name.trim().is_empty()` branch | `blank_tunnel_name_from_lookup_uses_fallback` |
| TRP-07 | P3 | docs / matrix | Route prompt still Pending | Update 07 / 16 / matrix / README | doc review |

### Simplify delta (post-adversarial)

| ID | Sev | Location | Change | Verification |
|---|---|---|---|---|
| S-01 | — | `from_choices` | Remove unnecessary `mut` on builder | compile |
| S-02 | — | `wormhole-ui` glue | Re-export `CancellationToken` from session (no extra dep) | ui lib tests |
| S-03 | — | tests | `apply_tunnel_route_choice` direct unit coverage | `apply_choice_maps_direct_and_cancel` |

Production deltas from TRP-01–TRP-03 → adversarial re-looped to 2 clean.

---

## Rejected candidates

| Candidate | Reason |
|---|---|
| Wire `resolve_tunnel_route` into `SessionOrchestrator::connect` | Explicit non-goal this milestone; callers (tree/QC VMs) still Pending |
| Async `resolve_tunnel_route` + channel prompt | Lab Fake is sync; OTP/SAML channels are separate surfaces |
| GPUI / WinUI ContentDialog | Out of scope — Fake UI only |
| Map user Cancel to `SessionError::Cancelled` | C# returns `null` profile (silent abort); token cancel stays `Err(Cancelled)` |
| Propagate lookup `Err(Other)` to caller | C# cosmetic name failure must not block routing |
| Store full connection/tunnel names in Fake Debug | User rule: Debug lengths/ids only |
| Put core logic only in `wormhole-ui` | Connect-path glue belongs in `wormhole-session`; ui only maps `AppSettings` |

---

## Adversarial clean passes (2 required)

### Clean pass 1 — order: contract → boundary → state → concurrency → security

- Setting off + tunnel disabled skip prompt; tunnel on + setting on exercises Fake script.
- AllowTunnel unchanged; PreferDirect flips only `tunnel_enabled`; Cancel / exhausted / missing prompt → `None`.
- Lookup missing / error / blank name → generic label; lookup cancel → no prompt.
- Pre- and post-prompt cooperative cancel paths pinned.
- Debug omits names and credential-shaped fields.

### Clean pass 2 — order: security → concurrency → state → boundary → contract

- Re-ran attack order swap; no new findings after TRP fixes + simplify delta.
- Mutex-backed Fake UI: single-threaded tests only (Lab); no poison path in production glue.

---

## Iterative-review-simplify clean passes (3 required)

1. Post-TRP fixes: removed unsafe adapter; lookup swallow; post-prompt cancel check.
2. S-01 / S-02 / S-03 test and dependency simplifications — suite green.
3. Doc-only delta (ledger / matrix / spike) — no code change; third clean simplify.

---

## Test command

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-session
cargo test -p wormhole-ui --lib
```

**Counts:** `tunnel_route_prompt` module **18** unit tests; full session lib **85**;
orchestrator_fakes **34**; wormhole-ui lib **315**.
