# Adversarial ledger — VNC framebuffer + input queue

Scope:
- `rust/crates/wormhole-vnc/` — `RawPixelBuffer`, `DamageTracker`, `InputEventQueue`, `VncSession` wiring
- `docs/migration/09-vnc.md`

Out of scope: C# VNC UI; live TCP/`vnc-rs` client I/O; GPUI blit; Zrle/Tight/CopyRect.

Baseline (before review edits): `cargo test -p wormhole-vnc` **28** passed; `--features engine` **29** passed.

## Findings

| ID | Sev | Location | Issue | Evidence | Disposition |
|---|---|---|---|---|---|
| VFB-001 | P1 | `DamageRect::union` | `as u16` truncation when union span > `u16::MAX` → empty/wrong damage | Adjacent `(0,0,MAX,1)` + `(MAX,0,1,1)` → width `0` | **Fixed** — overflow → full-plane over-damage `(0,0,MAX,MAX)` + regression |
| VFB-002 | P1 | `RawPixelBuffer::resize` | `saturating_mul` could leave `pixels.len()` short vs `width*height*bpp` → blit panic | Hostile dims on narrow `usize` | **Fixed** — `checked_mul`; fail closed to `0×0` |
| VFB-003 | P1 | `blit_raw` indexing | Unchecked row offsets could panic if store/len drift | Slice panic path | **Fixed** — checked offsets + end ≤ `pixels.len()`; reject on failure |
| VFB-004 | P2 | `VncSession` | No `Debug`; attack focus requires session types not leak password | Public `options.password` | **Fixed** — custom `Debug` redacts via options; summarizes FB/input (no pixel dump) |
| VFB-005 | P2 | `InputEventQueue::new(0)` | `assert!(capacity > 0)` panics | Hostile capacity | **Fixed** — coerce `0 → 1`; document drop policy (full → `InputQueueFull`, queue unchanged) |
| VFB-006 | P2 | tests / docs | Missing RGBA multi-row stride, exact-edge OOB, vertical adjacency; docs soft on live RFB/hardware | Attack focus lanes | **Fixed** — tests + `09-vnc.md` non-goals / drop policy / OOB reject |
| VFB-007 | P2 | `raw_rect_byte_len` | Saturating length could disagree with true rect size | Overflow → wrong `expected` | **Fixed** — returns `Option`; blit errors on `None` |
| VFB-008 | P2 | `negotiate_security` | Failure left `Negotiating`; success after `Connected` stuck session | State atomicity | **Fixed** — restore prior on err; reject when `Connected`/`Closed` |
| VFB-009 | — | Corner-only AABB touch merges | Inclusive touch is 8-neighbor | Over-damage only | **Rejected** — intentional; comment + `damage_merge_corner_touch_over_damages` pin |
| VFB-010 | — | Unbounded disjoint damage list | Hostile 1×1 spam grows `Vec` | No cap | **Rejected** — deferred to live engine path; spike has no network feed |
| VFB-011 | — | `VncPassword` zeroize-on-drop | Secret in `String` | Memory scrubbing | **Rejected** — scaffold; no engine I/O yet |
| VFB-012 | — | OOB blit “clamps” | Spec wording vs reject | Current reject is safer than silent clamp | **Rejected** — reject documented; no buffer overrun |

## Fixes applied

- `framebuffer.rs`: safe union, checked resize/blit, RGBA/OOB/overflow/corner/vertical tests
- `input.rs`: capacity coerce, documented drop policy, full-reject leaves queue unchanged
- `session.rs`: redacting summarized `Debug`, negotiate rollback + connected/closed guard
- `engine.rs` / `lib.rs`: whitespace normalize; engine still presence-only
- `docs/migration/09-vnc.md`: drop policy, OOB reject, no live RFB/UI/hardware-gate claims; both test commands

## Gate record

### Adversarial loop

| Cycle | Strategy | Accepted findings | Result |
|---|---|---|---|
| Adv-1 | Contract → boundary → state → concurrency → security → integration → perf → tests | VFB-001…006 | Fixed; reset |
| Adv-2 | Reverse: security/Debug → state → checked lengths → tests | VFB-007, VFB-008 (partial) | Fixed; reset |
| Adv-3 | Forward: renegotiate-after-connect | VFB-008 complete | Fixed; reset |
| Adv-4 | Reverse: secrets, queue drop, docs non-goals, engine optional | None | Clean (1/2) |
| Adv-5 | Boundary: damage merge / OOB / stride / capacity | None (VFB-009…012 rejected) | Clean (2/2) |

### Iterative-review-simplify (after adversarial clean)

| Cycle | Reuse | Efficiency | Quality/Bugs | Accepted | Result |
|---|---|---|---|---|---|
| Sim-1 | Negotiate rollback via single `?` closure | Hoist `x_bytes` out of blit row loop | Fix adjacency comment (corner over-damage); normalize `engine.rs` | Yes → reset | Fixed |
| Sim-2 | — | — | Pin corner-touch merge with regression test | Yes → reset | Fixed |
| Sim-3 | No missed helpers | No hot-path I/O | No further validated issues | None | Clean (1/3) |
| Sim-4 | Same | Same | Docs/tests aligned with drop + OOB contracts | None | Clean (2/3) |
| Sim-5 | Same | Same | Diff hygiene in-scope | None | Clean (3/3) |

Simplify changed code → post-simplify adversarial re-run:

| Cycle | Strategy | Accepted | Result |
|---|---|---|---|
| Adv-R1 | Delta: negotiate closure, blit hoist, corner test, docs | None | Clean (1/2) |
| Adv-R2 | Security/Debug + queue + damage overflow re-check | None | Clean (2/2) |

No further simplify edits after Adv-R*; prior Sim-3…5 remain the completed simplify gate.

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-vnc
cargo test -p wormhole-vnc --features engine
```

Result: **pass** — default **37** tests; `--features engine` **38** tests (includes `engine_feature_links_vnc_rs`).

## Remaining blockers

- Live VNC TCP / encodings still deferred (`engine` is presence-only; `live_client_available() == false`).
- Damage-list cap under hostile update floods deferred to engine integration.
- Context7 MCP unavailable in this environment; `vnc-rs` pin left as previously documented.
