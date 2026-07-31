# Adversarial ledger — FocusBroker + a11y (lab gates 7–8)

Scope: `rust/crates/wormhole-surface-win/src/focus/`, `rust/crates/surface-lab/` gate07/gate08 + `gpui_host` a11y hooks, `docs/migration/08-focus-a11y.md` (cross-links with `08-ui.md` / `native-surface-broker.md`)  
Baseline: `cargo test -p wormhole-surface-win focus` green (8 tests) before review; feature matrix default/webview/rdp/gpui check green after fixes  
Design SoT: `docs/migration/native-surface-broker.md` reconnect/focus rules; C# `RdpSurfaceHost._focusPushed`, `RdpHostForm.RequestFocus`, `OnSessionAutoReconnected`  
Preserved: never `SetFocus(NULL)`; AutoReconnected must not steal focus; no C# mutation; no RDP OLE rewrite

## Findings

| ID | Sev | Location | Issue | Evidence | Disposition |
|---|---|---|---|---|---|
| FA-001 | P1 | `focus/broker.rs` + tests | Failed / null cold-connect could be confused with latch burn; no regression that Failed leaves latch clear | Code already only latched on `Applied`, but untested; Retry path unpinned | **Fixed** — tests: null cold, `fail_next` then retry |
| FA-002 | P1 | docs `08-focus-a11y.md` + `focus/mod.rs` | Docs claimed latch is why AutoReconnected skips; impl skips **by connect kind** (latch only blocks duplicate ColdOrRetry) | Code vs C# `OnSessionAutoReconnected` (never `TryFocusSession`) | **Fixed** — docs + module/broker comments |
| FA-003 | P2 | broker tests | AutoReconnected before cold, chrome handoff clearing latch, explicit RDP request burning latch, missing-HWND paths unpinned | Attack lanes state/contract | **Fixed** — focused regressions |
| FA-004 | P2 | broker tests | Null HWND only covered for Rdp owner | Boundary lane | **Fixed** — all owners + AutoReconnected(null) short-circuit |
| FA-005 | P2 | `08-focus-a11y.md` / `native-surface-broker.md` / `08-ui.md` | Lab gate 7–8 vs broker spike gate 5 numbering collision; `08-ui.md` same `08-*` prefix | Doc accuracy attack | **Fixed** — disambiguation notes; broker §5 renumber callout; `08-ui` pointer |
| FA-006 | P3 | `gate08_a11y.rs` | Identical `STATUS` under both `gpui` cfg arms | Dead cfg noise | **Fixed** — single `Partial` |
| FA-007 | P3 | `gpui_host/lab.rs` | `ElementId` rejected `(&str, u8)` under current GPUI pin — broke `--features gpui` matrix | `cargo check -p surface-lab --features gpui` | **Fixed** — cast splitter id tag to `u32` |
| FA-008 | P3 | `gate08_a11y::run_smoke` docs | Claimed “optionally boot” AccessKit but never boots (boot is `main` opt-in) | Headless / a11y attack | **Fixed** — docstring clarifies non-blocking smoke |
| FA-009 | — | `FocusReason` unused in policy | Carried on request but not matched | API reserved for diagnostics | **Rejected** — keep for callers; documented |
| FA-010 | — | `RdpOverlayHost::request_focus` bypasses broker | Convenience path; latch is caller's job | Lab stand-in; gate7 smoke uses broker | **Rejected** — documented prefer-broker; no OLE rewrite |
| FA-011 | — | Dual null checks (broker + ops + win32) | “Duplication” | Defense in depth vs SetFocus(NULL) | **Rejected** — intentional |

## Fixes applied

- `focus/broker.rs` — AutoReconnect-vs-latch docs; regressions (null/fail latch, handoff, explicit RDP, missing HWND, all-owner null, AutoReconnected null)
- `focus/mod.rs` — cold-connect order wording
- `surface-lab` gate07 smoke text; gate08 STATUS/docs; `lab.rs` ElementId `u32`
- `docs/migration/08-focus-a11y.md`, `08-ui.md`, `native-surface-broker.md` §5 cross-links

### Out-of-scope unblocks (concurrent `wormhole-sftp` land)

Workspace became unloadable mid-review (`russh` feature `dep:tokio` on non-optional tokio; `russh-sftp` needing `chrono ^0.4.44` vs pin `=0.4.41`). Minimal unblocks so focus verification could finish:

- `wormhole-sftp/Cargo.toml` — drop `dep:tokio` from `russh` feature
- `rust/Cargo.toml` — `chrono` `=0.4.41` → `=0.4.44`

## Gate record

### Adversarial loop

| Cycle | Strategy | Accepted findings | Result |
|---|---|---|---|
| Adv-0 (initial) | Contract → boundary → state → concurrency → security → integration → perf → tests | FA-001…008 | Fixed; counter reset |
| Adv-1 | Same lanes on fixed tree; AutoReconnected(null) boundary | FA-004 widen | Fixed; counter reset |
| Adv-2a | Contract→…→tests | None | Clean (1/2) |
| Adv-2b | Reverse: tests-as-oracles → C# parity → Win32 GetLastError=0 → a11y headless opt-in → docs | None | Clean (2/2) |

### Iterative-review-simplify

| Cycle | Reuse | Efficiency | Quality/Bugs | Accepted | Result |
|---|---|---|---|---|---|
| Sim-fix | Dropped redundant single-owner null test (covered by all-owners) | — | gate08 smoke docstring lied about boot | **Fixed** | Reset |
| Sim-1 | Dual null checks kept (defense) | No hot-path I/O | Latch/kind invariants intact | None | Clean (1/3) |
| Sim-2 | No new FocusOps abstraction | Fine | AccessKit still opt-in only | None | Clean (2/3) |
| Sim-3 | Docs match impl; `08-ui` separate | Fine | Feature matrix compile | None | Clean (3/3) |

### Adversarial re-loop (after simplify docstring)

| Cycle | Strategy | Accepted | Result |
|---|---|---|---|
| Adv-R1 | Delta: gate08 docstring + prior invariants | None | Clean (1/2) |
| Adv-R2 | Reverse: never SetFocus(NULL); AutoReconnected skip-by-kind; latch terminal-only | None | Clean (2/2) |

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-surface-win focus
cargo test -p wormhole-surface-win
cargo test -p wormhole-surface-win --features rdp
cargo check -p surface-lab
cargo check -p surface-lab --features webview
cargo check -p surface-lab --features rdp
cargo check -p surface-lab --features gpui
cargo run -p surface-lab
```

Result: **pass** — 15 focus unit tests; 32 default crate tests / 35 with `--features rdp`; feature matrix (default/webview/rdp/gpui) green; default `surface-lab` run prints gate 7–8 smokes without AccessKit event loop.

## Deferred

- Hardware evidence packs (x64/ARM64) for gate-checklist pass
- Production shell wiring of FocusBroker into session VMs
- Full AxHost-child HWND (lab uses overlay stand-in until OLE embedding)
