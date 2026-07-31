# Adversarial ledger — VNC `clipboard_glue` cut-text stub

**Scope:** `rust/crates/wormhole-vnc/src/clipboard_glue.rs` (+ `VncError::{ClipboardEmpty,ClipboardTooLarge}`, `VncSession` outbound queue / local buffer / `Debug` / `close` / drain helpers), `docs/migration/09-vnc.md`  
**Authority:** adversarial-review-fix (edit in scope; no live RFB / HardwarePass; no wormhole-ui/storage/app churn; no git commit/push)  
**Out of scope:** OS clipboard / GPUI sync; live ClientCutText wire I/O; C# `HandleServerClipboardUpdate` (still no-op); terminal paste pump  
**Baseline (pre-fix):** `cargo test -p wormhole-vnc` **92** passed; impl from `cda0e48a-3e88-4aa1-acd7-a8ed6fd8fce0`.

Attack focus:

- Outbound ClientCutText → Fake send queue; inbound ServerCutText → local buffer
- Soft **1 MiB UTF-8 byte** cap (terminal paste / C# parity); empty fail-closed
- Session gate (`NotConnected`) before empty/oversize; no send / buffer unchanged
- `Debug` / `Display` / errors: lengths only (secrets-adjacent)
- Fake only — no live VNC

---

## Findings

| ID | Sev | Location | Issue | Evidence | Disposition |
|---|---|---|---|---|---|
| VNC-CLIP-001 | P2 | `clipboard_glue` tests | Multi-send FIFO + `take_outbound_cut_texts` drain unpinned | Fake engine drain contract | **Fixed** — `outbound_accumulates_fifo_and_take_drains` |
| VNC-CLIP-002 | P2 | glue + tests | Error precedence (NotConnected vs empty/oversize) unpinned | Hostile empty/oversize while Idle/Negotiating | **Fixed** — session-gate-first docs + `not_connected_precedes_empty_and_oversize` |
| VNC-CLIP-003 | P2 | tests | Cap documented as UTF-8 bytes but only ASCII `repeat` pinned | Scalar-count confusion (emoji 4-byte) | **Fixed** — `utf8_byte_cap_not_scalar_count` + 1 MiB constant pin |
| VNC-CLIP-004 | P3 | `09-vnc.md` | Fail-closed condition/error table missing (forwarder had one) | Docs accurate attack lane | **Fixed** — table + ledger link + FIFO/`close` notes |
| VNC-CLIP-005 | P3 | tests | `Display` of clipboard errors / `local_clipboard_text` under-pinned | Secrets-adjacent Display path | **Fixed** — `clipboard_errors_display_sizes_only`, `local_clipboard_text_helper_matches_buffer` |
| VNC-CLIP-006 | P3 | rustdoc | `[ClipboardTooLarge]` link incomplete after gate note | Doc link hygiene | **Fixed** — `VncError::ClipboardTooLarge` |
| VNC-CLIP-007 | P3 | tests | Cross-direction fail-closed independence under-pinned | Outbound empty must not clear local; inbound oversize must not clear queue | **Fixed** — `directions_fail_closed_independently` |
| VNC-CLIP-008 | — | Unbounded outbound `Vec` | Repeated sends grow until `close`/drain | Lab Fake; input queue is separate bounded path | **Rejected** — out of stated 1 MiB/empty contract; drain/`close` clear |
| VNC-CLIP-009 | — | Share const with `wormhole-terminal` | Duplicated `1024 * 1024` | Would add crate dep | **Rejected** — cross-crate churn; pin test documents parity |
| VNC-CLIP-010 | — | Pub fields bypass glue | Manual `outbound_cut_texts.push` skips Connected check | Same Lab Fake pattern as other session fields | **Rejected** — `send_*` / `apply_*` are the API |
| VNC-CLIP-011 | — | Whitespace-only / NUL bodies | Non-empty exotic text accepted | Empty = `utf8_len == 0` only | **Rejected** — matches terminal paste empty contract |

---

## Fixes applied

- Regression tests: FIFO drain, NotConnected precedence, UTF-8 byte (not scalar) cap, 1 MiB constant pin, Display sizes-only, local peek helper, cross-direction independence
- `09-vnc.md`: fail-closed table, byte-cap wording, ledger link
- Simplify: `cut_text_when_connected` shared gate+validate; module docs say “byte” cap
- Ledger + README index entry

---

## Gate record

### Adversarial loop

| Cycle | Strategy | Accepted findings | Result |
|---|---|---|---|
| Adv-1 | Contract → boundary → state → concurrency → security → integration → perf → tests | VNC-CLIP-001…005 | Fixed; reset |
| Adv-2 | Reverse: security → integration → docs → boundaries | VNC-CLIP-006, VNC-CLIP-007 | Fixed; reset |
| Adv-3 | Forward: C# no-op parity + fail-closed table + Fake + Debug lengths | None | Clean (1/2) |
| Adv-4 | Reverse: exports, error Display, direction independence, engine feature green | None | Clean (2/2) |

### Iterative-review-simplify (after adversarial clean)

| Cycle | Reuse | Efficiency | Quality/Bugs | Accepted | Result |
|---|---|---|---|---|---|
| Sim-1 | `cut_text_when_connected` for send/apply | No extra I/O | Module docs “byte” cap | Yes → reset | Fixed |
| Adv-R* | Post-simplify delta | — | Helper preserves gate-before-validate | None | See below |
| Sim-2 | Keep local const (no terminal-crate share) | Reject AsRef alloc tradeoff | Tests cover public API via helper | None | Clean (1/3) |
| Sim-3 | Thin `local_clipboard_utf8_len` kept | Hot path N/A (Lab Fake) | Diff hygiene in-scope | None | Clean (2/3) |
| Sim-4 | Same | Same | No further validated churn | None | Clean (3/3) |

Post-simplify adversarial re-loop:

| Cycle | Strategy | Accepted | Result |
|---|---|---|---|
| Adv-R1 | Delta: `cut_text_when_connected` precedence + borrow | None | Clean (1/2) |
| Adv-R2 | Security lengths-only + fail-closed table vs helper | None | Clean (2/2) |

No further simplify edits after Adv-R → Sim-2…4 remain the completed simplify gate.

---

## Regression tests (`clipboard_glue::tests`)

- `outbound_accumulates_fifo_and_take_drains`
- `not_connected_precedes_empty_and_oversize`
- `utf8_byte_cap_not_scalar_count`
- `max_cap_matches_terminal_paste_and_csharp_1mib`
- `clipboard_errors_display_sizes_only`
- `local_clipboard_text_helper_matches_buffer`
- `directions_fail_closed_independently`
- Existing: outbound/inbound happy path, empty/oversize both ways, exact limit, not Connected, close clears, Debug redaction, validate helper

---

## Final verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-vnc
cargo test -p wormhole-vnc --features engine
```

Result: **pass** — default **100** tests; `--features engine` **101** tests. `git diff --check` clean on in-scope paths.

## Remaining blockers

- OS clipboard sync / live ClientCutText wire I/O still deferred (Lab Fake queue + local buffer only).
- C# `HandleServerClipboardUpdate` remains a no-op until a future surface host wires this stub.
- Context7 MCP unavailable in this environment; no crate pin change required for this stub.
