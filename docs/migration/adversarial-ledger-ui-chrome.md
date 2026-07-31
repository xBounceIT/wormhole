# Adversarial ledger — wormhole-ui GPUI chrome

Scope (ONLY):
- `rust/crates/wormhole-ui/` (`gpui_host`, `ShellState` integration, `PaneLayoutSink`, example)
- `docs/migration/08-ui.md`

Out of scope: C#; hardware gate pass claims; mutating other crates.

Baseline (before review edits): `cargo test -p wormhole-ui` 17 ok; `cargo test -p wormhole-ui --features gpui` 21 ok; example check green. Boot already used `gpui_platform::application()`. Context7 MCP unavailable; GPUI pins from `deps-pins.md`.

## Findings

| ID | Sev | Location | Issue | Evidence | Disposition |
|---|---|---|---|---|---|
| UIC-001 | P1 | `chrome.rs` tab strip | Tab `ElementId` used strip **index** → collide/reuse after close/reorder | `("tab", idx as u64)` | **Fixed** — `tab_element_key(uuid)` stable SharedString |
| UIC-002 | P1 | `chrome.rs` workspace / compute | Empty / partial pane sets invented `PaneId(0..=3)` via `unwrap_or` | `0 \| 1` branch + quad `_` arm | **Fixed** — empty placeholder UI; only real panes; empty compute → `[]` |
| UIC-003 | P1 | Chrome UI actions | Pane ≤4 / tab↔pane coordination not exercised as headless UI actions; no close-pane control | Split swallowed `Err`; no close | **Fixed** — `action_split_pane` / `action_close_focused_pane` / `action_open_demo_tab` + Close pane button + regression |
| UIC-004 | P2 | `ShellState` / tabs | Close pane then resplit could silently revive stale tab→pane if clear omitted | Attack: reuse lowest free `PaneId` | **Fixed** (already cleared) + regression `close_pane_then_resplit_does_not_revive_tab_assignment` |
| UIC-005 | P2 | `assign_tab_pane` after close | Stale pane id after close not pinned | Hostility: assign closed id | **Fixed** — regression `assign_after_close_rejects_stale_pane` |
| UIC-006 | P2 | `notify_layout_sink` | Every render notified sink even when bounds unchanged | Broker spam / SetWindowPos churn | **Fixed** — skip identical ticks |
| UIC-007 | P2 | `apply_layout` / compute | NaN / negative / Inf content extents → unsound physical casts | Hostile `LogicalRect` | **Fixed** — `sanitize_origin` / `sanitize_extent` inside `compute_pane_updates` |
| UIC-008 | P2 | `ShellChrome::shell_mut` | Unused footgun: `&mut ShellState` can bypass coordinated close | Grep unused; `workspace.close_pane` desyncs tabs | **Fixed** — removed |
| UIC-009 | P3 | Theme / palette | Plan tokens must drive chrome accent/bg/text | Attack: hardcoded diverge from `THEME` | **Fixed** — `palette_tracks_theme_plan_tokens` |
| UIC-010 | P3 | Docs verification | Only `cargo check --features gpui`; user requires tests + example | Feature-matrix attack | **Fixed** — `08-ui.md` verification lists default + gpui tests + example check |
| UIC-011 | — | `open_window(...).expect` | Panic vs `Result` on boot | Inside `application().run` callback | **Rejected** — same surface-lab pattern; API does not surface window-open `Result` cleanly |
| UIC-012 | — | Mutex poison on sink | Poisoned lock skips notify | Lab sink | **Rejected** — intentional soft-fail for lab |
| UIC-013 | — | Raw `TabStrip::assign_pane` | Still allows any `PaneId` | Prefer `ShellState::assign_tab_pane` | **Rejected** — documented; chrome uses coordinated API |
| UIC-014 | — | Hardware DPI / Mica gate | Lab smoke ≠ gate pass | User constraint | **Rejected** — doc + example explicitly do not claim gate pass |

## Fixes applied

- Stable tab/pane ElementIds; empty-workspace safe layout + sink; no invented pane ids
- Testable UI actions + Close pane; pane ≤4 + tab clear regressions
- Identical-tick sink skip; NaN/negative layout sanitization; remove `shell_mut`
- Theme palette regression; `LogicalRect` export; `horizontal_pane_pair` / `toolbar_button` simplify
- Docs `08-ui.md` aligned with verification commands

## Gate record

### Adversarial loop

| Cycle | Strategy | Accepted findings | Result |
|---|---|---|---|
| Adv-1 | Contract → boundary → state → concurrency → security → integration → perf → tests | UIC-001…007, 009–010 | Fixed; reset |
| Adv-2 | Reverse: feature flags → ElementId → sink → shell_mut → NaN extents → 2/3-pane compute | UIC-007 (sanitize), UIC-008 (`shell_mut`), 2/3-pane tests | Fixed; reset |
| Adv-3 | Forward lanes on post-fix chrome | None | Clean (1/2) |
| Adv-4 | Reverse: secrets/logging, boot `gpui_platform`, pane≤4 UI actions, empty sink, theme | None | Clean (2/2) |

### Iterative-review-simplify (after adversarial clean)

| Cycle | Reuse | Efficiency | Quality/Bugs | Accepted | Result |
|---|---|---|---|---|---|
| Sim-1 | Sanitize once in `compute_pane_updates`; `.id(pane_element_key)` | Drop `updates.clone()` in notify | Centralize sanitization | Yes → reset | Fixed |
| Sim-2 | `horizontal_pane_pair` + `toolbar_button` | — | Drop redundant mutex-only sink test; unused import | Yes → reset | Fixed |
| Sim-3 | Toolbar refresh+notify fold — rejected (not worth churn) | No hot-path I/O | No validated bugs | None | Clean (1/3) |
| Sim-4 | Same | Same | Diff hygiene / feature matrix ok | None | Clean (2/3) |
| Sim-5 | Same | Same | In-scope only | None | Clean (3/3) |

### Post-simplify adversarial re-run (required)

| Cycle | Strategy | Accepted | Result |
|---|---|---|---|
| Adv-R1 | Delta: pair helper, toolbar helper, sanitize-in-compute, notify move | None | Clean (1/2) |
| Adv-R2 | Reverse on final surface | None | Clean (2/2) |

No further simplify edits after Adv-R*; simplify’s three clean cycles remain the last simplify run.

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-ui
cargo test -p wormhole-ui --features gpui
cargo check -p wormhole-ui --example wormhole-ui-lab --features gpui
# Optional visual smoke (blocks on event loop; does NOT claim hardware gate pass):
# cargo run -p wormhole-ui --example wormhole-ui-lab --features gpui
```

Result: **pass** — default **20** tests; `--features gpui` **31** tests; example check green. Pre-existing workspace warning: `proc-macro-error2` future-incompat (upstream). `git diff --check` clean for scoped paths.

## Residual notes

- Hardware DPI / Mica evidence remains on surface-lab / gate-checklist — this lab is visual smoke only.
- `NativeSurfaceBroker` HWND parenting still non-goal (trait + bounds only).
