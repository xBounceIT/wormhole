# Adversarial ledger — Quick Connect *delta*

Scope (ONLY):
- `rust/crates/wormhole-ui/src/quick_connect/**`
- `docs/migration/21-quick-connect.md` (as needed)

Delta under review (agent d5369d71):
- `tunnel_selection` / `set_tunnel_selection` (Inherit → No tunnel; serial forced off)
- QC chrome labels + SSH auto-sudo On/Off
- `QuickConnectResult` Debug (and Display) password redaction
- Tests: RDP+tunnel, tunnel API, labels, Debug/Display

Out of scope: `ConnectionEditorState` internals beyond what QC wraps; GPUI chrome; see full-module [`adversarial-ledger-quick-connect.md`](adversarial-ledger-quick-connect.md).

Baseline: `cargo test -p wormhole-ui quick_connect` green before delta fixes.

## Findings

| ID | Sev | Location | Issue | Evidence | Disposition |
|---|---|---|---|---|---|
| QCDC-001 | P2 | `tunnel_selection` | Serial getter did not clamp; `editor_mut` Config leaked past QC API | `set_protocol(Serial)` + `editor_mut().set_tunnel_selection(Config)` → getter returned Config | **Fixed** — Serial / `enabled=None` → `NoTunnel` |
| QCDC-002 | P2 | `set_tunnel_selection` | Inherit collapse depended on `allow_inheritance`; tamper kept Inherit | Flip `allow_inheritance=true` then `set_tunnel_selection(Inherit)` | **Fixed** — QC always remaps Inherit → NoTunnel |
| QCDC-003 | P2 | `set_protocol` | Leaving Serial revived `editor_mut`-planted Config as SSH tunnel | Serial + plant Config + `set_protocol(Ssh)` | **Fixed** — enter/leave Serial forces NoTunnel |
| QCDC-004 | P2 | `try_build` | Inherit-shaped + vestigial `config_id` could write non-NoTunnel fields | Tamper `enabled=None` + `config_id=Some` then accept | **Fixed** — normalize via QC tunnel API before write; `allow_inheritance=false` |
| QCDC-005 | P3 | `QuickConnectResult` | Attack focus requires password never in Display; only Debug existed | C# `ToString` redacts; Rust had Debug only | **Fixed** — `Display` mirrors C#; shared `PASSWORD_REDACTED` |
| QCDC-006 | — | Chrome labels | Speculative “claims UI shipped” | Docs Status/Non-goals say no GPUI; helpers are C# string parity | **Rejected** |
| QCDC-007 | — | `EnabledNoConfig` via QC setter | Rare editor sentinel still writable | Not offered by QC chrome contract; write path explicit | **Rejected** — out of delta attack focus |
| QCDC-008 | — | Edit `ConnectionEditorState` | Tempting to clamp Inherit in editor | User: don’t regress editor | **Rejected** — QC wrapper only |

## Fixes applied

- QC `tunnel_selection` / `set_tunnel_selection` enforce Serial + no-Inherit contracts
- `set_protocol` forces NoTunnel when entering **or** leaving Serial
- `try_build` normalizes tunnel through QC API before write
- `QuickConnectResult` `Display` + shared redaction token
- Regression tests: Display redact, Serial getter/`editor_mut`/leave, Inherit tamper + accept scrub
- Docs `21-quick-connect.md` tunnel/redaction notes updated

## Gate record

### Adversarial loop

| Cycle | Strategy | Accepted findings | Result |
|---|---|---|---|
| Adv-1 | Contract → boundary → state → security → integration → tests | QCDC-001, 002, 005 | Fixed; reset |
| Adv-2 | Reverse: secrets/Display → labels → Inherit/Serial → editor_mut | None (pre leave-Serial) | Clean (1/2)* |
| Adv-3 | Protocol-switch / leave-Serial / vestigial config on accept | QCDC-003, 004 | Fixed; reset |
| Adv-4 | Forward lanes on post-fix surface | None | Clean (1/2) |
| Adv-5 | Reverse: Debug/Display, chrome ship claims, editor untouched, test resistance | None | Clean (2/2) |

\* Adv-2 counted clean before Adv-3 found leave-Serial; counter reset after QCDC-003/004.

### Iterative-review-simplify (after adversarial clean)

| Cycle | Reuse | Efficiency | Quality/Bugs | Accepted | Result |
|---|---|---|---|---|---|
| Sim-1 | Fold Serial enter/leave; drop dead Inherit match arm; `PASSWORD_REDACTED` | — | — | Yes → reset | Fixed |
| Sim-2 | Extract normalize helper — rejected (2-line churn) | No hot-path I/O | No validated bugs | None | Clean (1/3) |
| Sim-3 | TargetField vs VisibleFields dedupe — rejected (pre-existing) | Same | Diff hygiene ok | None | Clean (2/3) |
| Sim-4 | Unify set_tunnel early-return — rejected (taste) | Same | In-scope only | None | Clean (3/3) |

### Post-simplify adversarial re-run (required)

| Cycle | Strategy | Accepted | Result |
|---|---|---|---|
| Adv-R1 | Delta: Serial fold, getter merge, redaction const, try_build normalize | None | Clean (1/2) |
| Adv-R2 | Reverse on final surface (password, Inherit, Serial leave, labels) | None | Clean (2/2) |

No further simplify edits after Adv-R*; three consecutive clean simplify cycles remain the last simplify run.

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-ui quick_connect
```

Result: **pass** — lib **25** QC unit tests + **3** connection_editor QC-filtered integration tests.

## Residual

- Broader QC adversarial may still land `adversarial-ledger-quick-connect.md`; this file is the **delta** review only.
- `EnabledNoConfig` remains reachable via QC setter / `editor_mut` (rejected above).
- Fixed unrelated bare-CR compile break in `tests/settings_store.rs` so package tests could run (not a QC delta finding).
