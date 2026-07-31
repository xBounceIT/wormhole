# Adversarial ledger — VNC input queue drain/coalesce on resize (`input_resize_glue`)

**Scope:**
- `rust/crates/wormhole-vnc/src/input_resize_glue.rs`
  (`drain_coalesce_on_resize` / `drain_discard_on_disconnect` /
  `resize_session_framebuffer` / `VncInputResizeGlue` / `FakeInputResizeSink`)
- `rust/crates/wormhole-vnc/src/lib.rs` exports + crate docs
- Docs: `09-vnc.md`, `feature-matrix.md`, `interop-inventory.md`, README ledger index

**Out of scope:** Live RFB / `vnc-rs` TCP send; rewriting `clipboard_glue` /
`auth_glue`; GPUI blit; orch VNC connect (`UnsupportedProtocol` remains).

**Authority:** full adversarial-review-fix (edit in scope; no child agents)  
**Impl:** parent agent  
**Baseline:** `cargo test -p wormhole-vnc` **105** passed (pre-impl)  
**Final:** `cargo test -p wormhole-vnc` **128** passed

Context7 MCP unavailable in this environment; no dependency pins changed.

---

## Gate summary

| Gate | Result |
|---|---|
| Adversarial clean passes | **2** consecutive (Adv-3/4) + **2** post-simplify re-adv (Adv-R1/R2) |
| Iterative-review-simplify clean passes | **3** consecutive (Sim-2…4 after Sim-1 fix) |
| `cargo test -p wormhole-vnc` | **pass** (128) |
| `auth_glue` / `clipboard_glue` rewritten? | **No** |

---

## Findings

| ID | Sev | Location | Issue | Evidence | Disposition |
|---|---|---|---|---|---|
| VIR-001 | P2 | tests | Closed-state resize fail-closed + FB non-clobber unpinned | Attack: Closed + seeded queue | **Fixed** — `closed_session_resize_fail_closed_queue_intact` |
| VIR-002 | P2 | tests | Report invariant `kept = drained - oob - coalesced` unpinned | Contract | **Fixed** — `report_invariant_held_after_mixed_pass` |
| VIR-003 | P2 | tests | OOB gap → remaining same-button coalesce unpinned | Coalesce policy | **Fixed** — `oob_gap_allows_remaining_same_button_coalesce` |
| VIR-004 | P2 | `resize_session_framebuffer` | `set_size` before drain → torn FB if re-enqueue failed | State atomicity | **Fixed** — drain/coalesce **then** `set_size` |
| VIR-005 | P3 | `09-vnc.md` | Session resize order omitted from policy table | Docs | **Fixed** — table row |
| VIR-006 | P3 | Fake `clear` / all-OOB empty | `clear` + `queue_empty_after` soft | Test resistance | **Fixed** — `fake_clear_resets_reports_and_all_oob_empties_queue` |
| VIR-007 | P3 | duplicate `debug_assert` | Dual invariant asserts | Simplify reuse | **Fixed** — drop asserts; unit test pins invariant |
| VIR-008 | — | Clamp OOB pointers | Spec could clamp | OOB reject matches Raw blit | **Rejected** — fail-closed drop documented |
| VIR-009 | — | Coalesce key down/up | Could drop redundant ups | Breaks server key state | **Rejected** — keys FIFO always |
| VIR-010 | — | Context7 MCP | Dep docs | Server unavailable | **Blocked** — no dep change needed |
| VIR-011 | — | Rewrite clipboard/auth | User gate | Prefer wormhole-vnc thin glue | **Rejected** — untouched |

---

## Fixes applied

- New `input_resize_glue.rs` — drain/coalesce policy + Fake sink + session helpers
- `lib.rs` / `Cargo.toml` — module + exports; crate description
- Docs `09-vnc.md` / feature-matrix / interop-inventory / README ledger link
- Attack-lane regressions (Closed, invariant, OOB-gap, Fake clear)
- Session resize order: input reshape before FB `set_size`

---

## Gate record

### Adversarial loop

| Cycle | Strategy | Accepted findings | Result |
|---|---|---|---|
| Adv-1 | Contract → boundary → state → concurrency → security → integration → perf → tests | VIR-001…005 | Fixed; reset |
| Adv-2 | Reverse: test resistance → Debug/secrets → Closed/Negotiating → docs | VIR-006 | Fixed; reset |
| Adv-3 | Forward: policy table + atomicity + orch untouched | None | Clean (1/2) |
| Adv-4 | Reverse: OOB no-clamp, key FIFO, auth/clipboard untouched, VIR-008…011 | None | Clean (2/2) |

### Iterative-review-simplify (after adversarial clean)

| Cycle | Reuse | Efficiency | Quality/Bugs | Accepted | Result |
|---|---|---|---|---|---|
| Sim-1 | Drop duplicate `debug_assert`; invariant in unit test | No I/O; single drain pass | Fake `clear` pin | VIR-006/007 | Fixed; reset |
| Sim-2 | Free fns shared by glue; no clipboard/auth touch | Shrink-only re-enqueue | Docs order row | None | Clean (1/3) |
| Sim-3 | Exports via `lib.rs` only | Counts-only reports | Diff hygiene in-scope | None | Clean (2/3) |
| Sim-4 | Same | Same | VIR-008…011 remain rejected/blocked | None | Clean (3/3) |

Post-simplify adversarial re-loop (Sim-1 changed code/tests):

| Cycle | Strategy | Accepted | Result |
|---|---|---|---|
| Adv-R1 | Delta: assert removal, Fake clear, resize order | None | Clean (1/2) |
| Adv-R2 | Attack lanes re-check + secrets Debug + auth/clipboard untouched | None | Clean (2/2) |

No further simplify edits after Adv-R* → Sim-2…4 remain the completed simplify gate.

---

## Regression tests (`input_resize_glue::tests`)

- Same-button coalesce keeps last; different buttons preserved
- OOB drop + keys FIFO; zero-size drops all pointers
- Exact-edge OOB (`x == width`); keys interrupt coalesce runs
- OOB gap allows remaining same-button coalesce
- Report invariant; empty queue noop; same-size still coalesces
- Disconnect discard idempotent; session resize Connected / fail-closed Idle+Negotiating+Closed
- Glue Fake record / disconnect-then-close / close-without-Fake-record
- Debug omits password + event bodies; Fake `clear`

---

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-vnc
```

Result: **pass** — **128** tests.

## Remaining blockers

- Live VNC TCP / encodings / GPUI blit still deferred.
- Context7 MCP unavailable; no dependency pins changed in this review.
