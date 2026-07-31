# Adversarial ledger — Tab close → orchestrator dispose

Scope (ONLY):
- `rust/crates/wormhole-app/src/session_tabs.rs` — `close_tab_and_dispose` / `close_tab_and_dispose_session` / `SessionBindings` / `SessionBinding` / `attach_handle` / `SessionTabGlueError`
- `rust/crates/wormhole-app/src/lib.rs` re-exports for the above (feature `ui`+`session`)
- `docs/migration/08-ui.md` dispose / `SessionBindings` / `attach_handle` contract lines
- `docs/migration/16-session-orchestrator.md` Session tab glue dispose + ledger link
- `docs/migration/README.md` index row
- this ledger

Out of scope: GPUI chrome / HardwarePass; `SessionTabBarState` internals (see [`adversarial-ledger-session-tabs.md`](adversarial-ledger-session-tabs.md)); open-only glue already closed in [`adversarial-ledger-session-tab-orch.md`](adversarial-ledger-session-tab-orch.md); live SSH/RDP/VNC engines; `SessionHandle::Drop` protocol dispose in `wormhole-session`.

**Attack focus:** Double close; unknown binding; handle id mismatch fail-closed; `ConnectOptions.session_id` stable while Connecting; cancel mid-connect; lease not dropped; attach orphan after mid-close; double attach overwrite.

Baseline (before review edits): `cargo test -p wormhole-app --lib session_tabs` — 20 ok; `cargo test -p wormhole-session` — 34 ok.

## Findings

| ID | Sev | Location | Issue | Evidence | Disposition |
|---|---|---|---|---|---|
| TCD-001 | P1 | `SessionBindings::attach_handle` | Sync attach silently overwrote an existing handle (drop without `close`) | Second attach path; lease/protocol orphan risk | **Fixed** — async attach; already-connected → close *new* handle + `DuplicateBinding` |
| TCD-002 | P1 | `attach_handle` unknown binding | Mid-close race returned `UnknownBinding` and left caller holding a live Connected handle | Cancel-then-connect-completes; prior test manually `close`d Failed only | **Fixed** — absent binding → `handle.close().await` + `Ok`; regression `attach_handle_unknown_disposes_orphan_lease` |
| TCD-003 | P2 | tests | Insert handle id mismatch unpinned | Attack: keyed under wrong `SessionId` | **Fixed** — `insert_connected_handle_id_mismatch_fail_closed` |
| TCD-004 | P2 | tests | Double-attach fail-closed unpinned | After TCD-001 | **Fixed** — `attach_handle_already_connected_fail_closed` |
| TCD-005 | P2 | `08-ui` / `16` / module docs | Attach orphan / double-attach contract missing | Docs only mentioned close unknown + mismatch | **Fixed** — docs + module rustdoc |
| TCD-006 | P2 | ledger / README | No tab-close-dispose ledger | Policy | **Fixed** — this file + README + `16` ledger list |
| TCD-007 | P3 | tests | Duplicated SSH+tunnel connect boilerplate | Two lease tests | **Fixed** — `connect_ssh_with_tunnel` helper (simplify) |
| TCD-008 | — | `insert` mismatch drops handle sync | No async `close` on fail path | Caller misuse; `TunnelLease` Drop still releases | **Rejected** — keep sync `insert`; lease covered by Drop |
| TCD-009 | — | Unify orch/UI `SessionId` | Two newtypes | Integration | **Rejected** — intentional; bit map via glue |
| TCD-010 | — | Parallel `&mut` race on bindings | Multi-threaded map | Composition root is exclusive `&mut` | **Rejected** — not a shared lock API |

## Fixes applied

- `attach_handle` → async; orphan dispose; double-attach fail-closed
- Removed unused `SessionTabGlueError::UnknownBinding` (attach no longer returns it)
- Regressions: orphan lease dispose, double attach, insert id mismatch; mid-connect uses `attach_handle` for orphan Failed
- Docs `08` / `16` / module rustdoc; README ledger index
- Simplify: `connect_ssh_with_tunnel`; fold `remove` match in `close_tab_and_dispose_session`

## Gate record

### Adversarial loop

| Cycle | Strategy | Accepted findings | Result |
|---|---|---|---|
| Adv-1 | Contract → boundary → state → concurrency → security → integration → perf → tests | TCD-001…006 | Fixed; reset |
| Adv-2 | Reverse: docs → lease Drop → double close → mismatch → mid-cancel → attach paths | None (TCD-008…010 noted) | Clean (1/2) — interrupted by simplify batch |
| Sim batch | Module doc, tunnel test helper, match fold (TCD-007) | Code change | **Adversarial reset** |
| Adv-R1 | Delta: async attach, helper, docs | None | Clean (1/2) |
| Adv-R2 | Forward attack list (double/unknown/mismatch/cancel/lease/attach) | None | Clean (2/2) |

### Iterative-review-simplify (after Adv-R*)

| Cycle | Reuse | Efficiency | Quality/Bugs | Accepted | Result |
|---|---|---|---|---|---|
| Sim-A | Helper retained; no further extract of delayed-SSH mid-connect | No hot-path I/O | Sync insert mismatch Drop noted (TCD-008) | None | Clean (1/3) |
| Sim-B | `close_tab_and_dispose_session` match already folded | Cancel+close order matches docs | Diff in-scope only | None | Clean (2/3) |
| Sim-C | Docs `08`↔`16`↔module aligned; no GPUI/HardwarePass | — | Public API honest (no dead `UnknownBinding`) | None | Clean (3/3) |

No further simplify edits after Adv-R*; final simplify three clean cycles completed with no code changes.

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-session
cargo test -p wormhole-app --lib session_tabs
```

Results at close: `wormhole-session` 34 passed; `wormhole-app --lib session_tabs` 23 passed.

**Not claimed:** HardwarePass / cutover / GPUI tab chrome wiring.
