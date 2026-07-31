# Adversarial ledger — SessionTabBarState / ProtocolBadge

Scope (ONLY):
- `rust/crates/wormhole-ui/src/session_tab_bar.rs`
- `rust/crates/wormhole-ui/src/lib.rs` re-exports for this module
- `docs/migration/08-ui.md` session tab list section
- `docs/migration/README.md` index link
- this ledger

Out of scope: GPUI chrome / `TabStrip` wiring; session orchestrator; `pane_layout` / workspace; C# production app.

**Attack focus:** DuplicateSession / UnknownSession fail-closed; close-active neighbor at edges (first/last/only); ProtocolBadge 1:1 with ProtocolType (Serial/VNC); empty/hostile unicode titles soft-handled; docs: pure state ≠ GPUI TabStrip shipped.

Baseline (before review edits): `cargo test -p wormhole-ui` — 82 lib + 17 connection_editor + 5 settings ok (8 `session_tab_bar` tests).

## Findings

| ID | Sev | Location | Issue | Evidence | Disposition |
|---|---|---|---|---|---|
| ST-001 | P2 | `close` edges | Close-active first / last / only neighbor selection unpinned | Attack lane; only middle covered | **Fixed** — `close_active_first…` / `close_active_last…` / `close_only_active…` |
| ST-002 | P2 | `open` / `activate` / `close` / `set_title` | Fail-closed Duplicate/Unknown did not assert full state freeze | Duplicate checked title only; unknown lacked before/after | **Fixed** — clone snapshots + double-close Unknown |
| ST-003 | P2 | `ProtocolBadge` | 1:1 with `ProtocolType` weak (no discriminant sweep; VNC label soft) | Attack: Serial/VNC | **Fixed** — discriminants `[0,1,3,4,5,6]`, ALL membership, Serial/VNC labels; SFTP=2 stays rejected |
| ST-004 | P2 | titles | Empty / hostile unicode not soft-handled (raw store; no contract) | Attack lane | **Fixed** — `sanitize_session_tab_title` strips `char::is_control()` on `new` / `open` / `set_title`; empty allowed |
| ST-005 | P2 | `08-ui.md` | Could read SessionTabBar as GPUI-shipped TabStrip | Attack: docs pure ≠ GPUI | **Fixed** — explicit **Not GPUI chrome**; lab still uses `TabStrip` |
| ST-006 | P3 | ledger / README | No adversarial ledger for session tabs | Policy | **Fixed** — this file + README link |
| ST-007 | — | BIDI / Cf format chars | Not stripped by `is_control()` | Hostile unicode lane | **Rejected** — soft-handle = Cc controls; Cf spoofing deferred to chrome |
| ST-008 | — | pub `SessionTabModel.title` field write | Bypass sanitize via struct literal | Misuse | **Rejected** — contract is `new` / `open` / `set_title` |
| ST-009 | — | Merge close neighbor with `TabStrip` | Duplicated neighbor math | Reuse pass | **Rejected** — different id / error types; keep parallel pure state |
| ST-010 | — | Unbounded title length | Megabyte title | Perf lane | **Rejected** — pure state; cap belongs at chrome / orchestrator |

## Fixes applied

- `sanitize_session_tab_title` + wire through `SessionTabModel::new` / `set_title`
- Fail-closed regressions (duplicate freeze, unknown freeze, double-close)
- Close-active edge regressions (first / last / only)
- ProtocolBadge discriminant 1:1 + Serial/VNC labels
- Docs: soft titles + fail-closed + not-GPUI; ledger + README
- Simplify: `active_tab` / `contains` reuse `get`

## Gate record

### Adversarial loop

| Cycle | Strategy | Accepted findings | Result |
|---|---|---|---|
| Adv-1 | Contract → boundary → state → concurrency → security → integration → perf → tests | ST-001…006 | Fixed; reset |
| Adv-2 | Reverse: docs claims → title sanitize → fail-closed → badges → close edges → exports | None (ST-007…010 rejected) | Clean (1/2) |
| Adv-3 | Forward lanes on post-fix surface | None | Clean (2/2) |

### Iterative-review-simplify (after adversarial clean)

| Cycle | Reuse | Efficiency | Quality/Bugs | Accepted | Result |
|---|---|---|---|---|---|
| Sim-1 | `active_tab` / `contains` → `get`; drop redundant ALL re-loop in badge test | No hot-path I/O | — | Yes → reset | Fixed |
| Sim-2 | (interrupted — Adv-R required after impl change) | — | — | — | — |

### Post-simplify adversarial re-run

| Cycle | Strategy | Accepted | Result |
|---|---|---|---|
| Adv-R1 | Delta: `get` reuse for `active_tab` / `contains` | None | Clean (1/2) |
| Adv-R2 | Reverse: fail-closed, titles, badges, close edges, docs ≠ GPUI | None | Clean (2/2) |

### Iterative-review-simplify (restart after Adv-R)

| Cycle | Reuse | Efficiency | Quality/Bugs | Accepted | Result |
|---|---|---|---|---|---|
| Sim-A | Parallel `TabStrip` neighbor kept | Lookup reuse retained | Method-order taste rejected | None | Clean (1/3) |
| Sim-B | Sanitize single helper | No alloc beyond title filter | Diff hygiene | None | Clean (2/3) |
| Sim-C | Docs/module contract aligned | — | In-scope only | None | Clean (3/3) |

No further simplify edits after Adv-R*; final simplify three clean cycles completed with no code changes.

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-ui
```

Result: **pass** — lib **101** (13 `session_tab_bar`); `connection_editor_validation` **17**; `settings_store` **5**. `git diff --check` clean for scoped paths.
