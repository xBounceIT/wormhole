# Adversarial ledger — GPUI gates 1–2 (surface-lab)

**Scope:** `rust/crates/surface-lab/` especially `gates/gpui_host/`, `gate01_window.rs`,
`gate02_panes.rs`; docs `01-surface-lab.md`. Minimal `wormhole-surface-win` only if
compile broke (not required this stream). No C#. Do **not** tick hardware
gate-checklist as passed.

**Date:** 2026-07-31  
**Gates completed:** 2 consecutive clean adversarial cycles + 3 consecutive clean
iterative-review-simplify cycles (after post-simplify adversarial re-check).

---

## Accepted findings → fixed

| ID | Sev | Finding | Fix |
|----|-----|---------|-----|
| A1 | P1 | Splitter drag divided by zero-sized content → NaN poisoned `h_split`/`v_split` (`f32::clamp` does not reject NaN) | Guard non-finite/≤0 axis length; `clamp_split_ratio` maps non-finite → 0.5 |
| A2 | P1 | Mouse-move drag used render-time `content` Bounds (stale after resize) | Recompute `LabRoot::content_bounds(window)` on each drag move |
| A3 | P1 | Duplicate ElementId `"split-h"` on top/bottom horizontal splitters | Distinct ids `("split-h", 0\|1)` / `("split-v", 0)` |
| A4 | P1 | Thin tests: only 150% DPI + partial theme; no clamp/DnD/degenerate coverage | Added 100/150/200% DPI, bad scale, clamps, swap permutation, chrome inset tests |
| A5 | P2 | Non-finite / non-positive scale factors produced garbage DPI math | `sanitize_scale_factor` → fallback 1.0 (96 DPI) |
| A6 | P2 | DnD ghost labeled by layout **slot**, not pane identity | Ghost carries `pane_id`; `PaneDrag { from_slot, pane_id }` |
| A7 | P2 | `compute_pane_logical` trusted raw ratios (defense-in-depth gap) | Clamp via `clamp_split_ratio` / shared `split_axis_sizes` |
| A8 | P2 | Status strip height was content-sized (`.py_1`) while drag math hardcoded `+22` | `STATUS_BAR_HEIGHT` constant + fixed-height status row |
| A9 | P1 | Split ratios updated state/status/`PhysicalBounds` but **visual** tiles stayed equal `flex_1` (drag did not resize panes) | `panes_body` sizes rows/columns from `split_axis_sizes` aligned with `compute_pane_logical` |

## Rejected findings

| ID | Reason |
|----|--------|
| R1 | Auto-pass gate-checklist hardware boxes — explicitly forbidden; lab remains `Partial` |
| R2 | Wire `NativeSurfaceBroker` on every layout tick — documented gate-2 TODO; out of this stream’s host-path scope |
| R3 | Absolute pixel min panes beyond ratio clamp — contract is ratio clamp + `min_w`/`min_h` chrome; broker hide on degenerate already exists |
| R4 | Theme toggle re-sets `MicaBackdrop` each click — redundant, harmless |
| R5 | Mutate C# / tick checklist / expand into gates 3–8 — out of scope |
| R6 | Fix parallel-agent `wormhole-sftp` feature design beyond lockfile chrono unblock — out of scope (see residual) |

## Simplify / iterative-review notes

| Pass theme | Outcome |
|------------|---------|
| Reuse | Shared `split_axis_sizes` for visual layout + logical bounds; exported helpers via `gpui_host` |
| Efficiency | Removed no-op zero-size `canvas` DPI stub |
| Quality | Public DevicePixels conversion (`i32::from` + saturating width/height); dropped redundant pre-clamp before `split_axis_sizes` |

Three consecutive clean iterative-review-simplify cycles after the last implementation edit (DevicePixels saturating cast + canvas removal already applied; subsequent cycles found no further validated changes).

## Invariant status

| Invariant | Status |
|-----------|--------|
| Boot uses `gpui_platform::application()` (not `Application::new`) | Pass |
| Custom title bar + `WindowControlArea` Drag/Min/Max/Close + occluded chrome buttons | Pass |
| DPI helpers correct at 100/150/200%; degenerate / bad scale sanitized | Pass (unit tests) |
| Splitter clamps 0.15–0.85; visual sizes match logical math | Pass (unit tests) |
| 4-pane `pane_order` permutation; DnD OOB/same-slot no-op | Pass (unit tests) |
| Default `cargo check` / `cargo check -p surface-lab` (no gpui) | Pass |
| `cargo check -p surface-lab --features gpui` | Pass |
| Hardware gate-checklist not claimed | Pass (still unchecked) |

## Verification commands

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo check
cargo check -p surface-lab
cargo check -p surface-lab --features gpui
cargo test -p surface-lab --features gpui
```

Results (2026-07-31): all green; **10** unit tests passed under `--features gpui`.

## Blockers / residual

- Hardware evidence at 100/150/200% on x64/ARM64 still required before checklist ticks.
- Broker layout-tick wiring and richer DnD remain TODOs in `gate02_panes.rs`.
- Parallel stream introduced `wormhole-sftp` / `russh-sftp` requiring `chrono` **0.4.44**; this stream ran `cargo update -p chrono --precise 0.4.44` to unblock workspace resolution (lockfile only).
