# Adversarial ledger — VNC session glue (`wormhole-vnc::session_glue`)

**Scope:** `rust/crates/wormhole-vnc/src/session_glue.rs` (`push_pointer_to_session` / `push_key_to_session` / `apply_framebuffer_rect` / `VncSessionGlue` / `FakeFramebufferDirtyNotify`), plus docs `09-vnc.md` / `feature-matrix.md` / `16-session-orchestrator.md` (orch `UnsupportedProtocol` untouched).  
**Authority:** adversarial-review-fix (edit in scope; no live RFB; no HardwarePass; no child agents)  
**Out of scope:** live TCP/`vnc-rs`, GPUI blit, C# `VncView`, `wormhole-session` orch connect path, framebuffer/input internals (see `adversarial-ledger-vnc-framebuffer.md`).  
**Baseline (pre-fix):** `cargo test -p wormhole-vnc` **63** passed.

Attack focus:

- Not `Connected` → `NotConnected` (Idle / Negotiating / Closed)
- Queue full → `InputQueueFull`, queue unchanged (no silent drop)
- Rect apply fail → `InvalidFramebufferUpdate`; dirty notify **not** invoked
- Dirty-after-error: prior notifies retained; no extra batch
- Input after `close()`: queue cleared; pointer/key/FB fail closed

---

## Findings

| ID | Sev | Location | Issue | Evidence | Disposition |
|---|---|---|---|---|---|
| VSG-001 | P2 | `session_glue` tests | Dirty-after-error under-pinned (Fake started empty; pixels unchanged / recovery untested) | Attack: dirty after error | **Fixed** — prior notify + OOB + wrong-len + recovery asserts |
| VSG-002 | P2 | `session_glue` tests | Input-after-close only checked one pointer; queue clear + FB path unpinned | Attack: input after close | **Fixed** — `input_and_framebuffer_fail_closed_after_close` |
| VSG-003 | P2 | `session_glue` tests | Queue-full only key-when-full; contents not asserted | Attack: queue full | **Fixed** — both directions + dequeue identity |
| VSG-004 | P2 | `feature-matrix.md` | VNC input/FB row omitted `session_glue` / dirty-notify / orch fail-closed | Docs in scope | **Fixed** — matrix row updated |
| VSG-005 | P3 | `09-vnc.md` | Session-glue bullet soft on Closed / queue-full / dirty-after-error | Docs accurate | **Fixed** — contract sentence expanded |
| VSG-006 | P3 | tests | Negotiating fail-closed unpinned; free-fn fail paths only happy-path | Boundary / integration | **Fixed** — negotiate path + `free_functions_fail_closed_*` |
| VSG-007 | P3 | tests | Zero-size “no notify” used Fake (also filters empty) — false confidence | Test resistance | **Fixed** — `CountingDirtyNotify` + `zero_size_rect_does_not_invoke_dirty_trait` |
| VSG-008 | — | `apply_framebuffer_rect` take-all damage | Successful zero-size could flush prior untaken damage | Mixed API only; glue always drains | **Rejected** — normal glue path drains each success |
| VSG-009 | — | Orch `UnsupportedProtocol` | Glue must not open orch connect | `16-session` + StubVncConnector | **Rejected as change** — confirmed untouched |
| VSG-010 | — | Context7 MCP | Dependency docs via Context7 | Server unavailable | **Blocked** — no dep version change needed |

---

## Fixes applied

- `session_glue.rs`: stronger attack-lane regression tests; negotiate-path Negotiating pin; `CountingDirtyNotify`; helpers (`oob_rect` / `empty_pointer`); module doc notes apply-error skip-notify
- `docs/migration/09-vnc.md`: fail-closed / queue-full / dirty-after-error wording
- `docs/migration/feature-matrix.md`: Lab `session_glue` + Fake dirty notify
- Ledger + README index entry
- Orch / `16-session-orchestrator.md`: no code change (already documents glue vs orch fail-closed)

---

## Gate record

### Adversarial loop

| Cycle | Strategy | Accepted findings | Result |
|---|---|---|---|
| Adv-1 | Contract → boundary → state → concurrency → security → integration → perf → tests | VSG-001…006 | Fixed; reset |
| Adv-2 | Reverse: test resistance → security/Debug → state/close → docs | VSG-007 | Fixed; reset |
| Adv-3 | Forward: attack focus matrix + free functions + orch untouched | None | Clean (1/2) |
| Adv-4 | Reverse: Fake vs Counting, queue identity, pixel integrity on apply err | None (VSG-008…010 rejected/blocked) | Clean (2/2) |

### Iterative-review-simplify (after adversarial clean)

| Cycle | Reuse | Efficiency | Quality/Bugs | Accepted | Result |
|---|---|---|---|---|---|
| Sim-1 | `oob_rect` / `empty_pointer`; `InputEvent` import; negotiate vs state poke | N/A (no I/O) | CountingDirtyNotify pins glue skip (not Fake filter) | Yes → reset | Fixed |
| Sim-2 | Helpers shared across glue + free-fn tests | No alloc churn on hot path | Module doc apply-error note | None new | Clean (1/3) |
| Sim-3 | No missed FramebufferDirtyNotify helpers | Hot path remains thin wrappers | Diff hygiene in-scope | None | Clean (2/3) |
| Sim-4 | Same | Same | Attack docs aligned with tests | None | Clean (3/3) |

Post-simplify adversarial re-loop (Sim-1 changed tests/docs):

| Cycle | Strategy | Accepted | Result |
|---|---|---|---|
| Adv-R1 | Delta: CountingDirtyNotify, negotiate path, helpers | None | Clean (1/2) |
| Adv-R2 | Attack lanes re-check + orch untouched | None | Clean (2/2) |

No further simplify edits after Adv-R* → Sim-2…4 remain the completed simplify gate.

---

## Regression tests (`session_glue::tests`)

- `input_fail_closed_when_not_connected` (Idle + Negotiating)
- `input_and_framebuffer_fail_closed_after_close`
- `invalid_framebuffer_update_skips_dirty_notify` (prior dirty + OOB + wrong-len + recovery)
- `input_queue_full_propagates_no_silent_drop` (key-full + pointer-full + identity)
- `free_functions_fail_closed_and_skip_dirty_on_apply_err`
- `zero_size_rect_does_not_invoke_dirty_trait` (CountingDirtyNotify)

---

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-vnc
```

Result: **pass** — **66** tests.

## Remaining blockers

- Live VNC TCP / encodings / GPUI blit still deferred.
- Context7 MCP unavailable; no dependency pins changed in this review.
