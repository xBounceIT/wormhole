# Adversarial ledger — Quick Connect → session orchestrator glue

Scope (ONLY):
- `rust/crates/wormhole-ui/src/quick_connect/session_connect.rs`
- Related QC exports in `quick_connect/mod.rs` / `PASSWORD_REDACTED` visibility in `state.rs`
- Docs `docs/migration/21-quick-connect.md`, `docs/migration/16-session-orchestrator.md`
- Tests under `session_connect` (+ related `quick_connect` as needed)

Out of scope: GPUI chrome; transient credential store / tab factory; live RDP OLE / VNC engine;
HardwarePass / cutover claims; unrelated `wormhole-tunnels` / secrets churn (compile unblockers only).

Baseline: `cargo test -p wormhole-ui --lib session_connect` (7 → 15 tests through review).
Context7 MCP unavailable; pins from workspace `Cargo.toml` / `deps-pins.md`.

Attack focus: password leakage in Debug/Display; empty host; tunnel flags; protocol mismatch;
RDP/VNC fail-closed; double-connect; options vs profile field drift.

## Findings

| ID | Sev | Location | Issue | Evidence | Disposition |
|---|---|---|---|---|---|
| QCSC-001 | P2 | `QuickConnectConnectRequest::Debug` | Nested `ConnectOptions::Debug` revealed `password: None` vs `Some("<redacted>")`; docs claimed always-`<redacted>` parity with `QuickConnectResult` | `format!("{request:?}")` with Serial (no password) lacked `<redacted>` / could leak presence | **Fixed** — always print `options_password: <redacted>`; add `Display`; surface tunnel flags without nesting full options |
| QCSC-002 | P2 | tests | Attack lanes under-tested: tunnel flags / SSH `TunnelArgsMissing` / RDP+tunnel before-tunnel / empty host / HTTPS / double-connect / Display / field parity | Brief attack list | **Fixed** — focused regressions (15 lib tests) |
| QCSC-003 | P2 | `21-quick-connect.md` / `16-session-orchestrator.md` | Tunnel-args caller ownership, redaction table, HTTPS, RDP+tunnel vs `TunnelArgsMissing`, prepare-before-connect for surface password under-documented | Doc vs impl drift | **Fixed** — docs + this ledger |
| QCSC-004 | — | Empty SSH host via `prepare_connect_ephemeral` | Fake SSH can “connect” to empty host | QC `try_build` already `HostRequired`; ephemeral path trusts caller like tree | **Rejected** — caller contract; RDP empty/whitespace pinned → `IncompleteNode` |
| QCSC-005 | — | Password unrecoverable after RDP/VNC `connect_*` | `ConnectOptions` dropped inside orchestrator; `UnsupportedProtocol` request omits secret | By design of stubs | **Rejected** as bug — documented: prepare + branch before connect for future surface hosts |
| QCSC-006 | — | Share `options_with_password` with `tree/open.rs` | Duplicated 3-line helper | QC→tree dep wrong direction; shared module over-abstract | **Rejected** |
| QCSC-007 | — | Gate empty host inside `from_ephemeral` | Defense in depth | Would need new `BuildError` shape; orchestrator already fail-closes RDP/VNC | **Rejected** |

## Fixes applied

- `session_connect.rs` — always-redact Debug/Display; module docs for tunnel args + RDP/VNC prepare-before-connect; `options_with_password` helper; drop redundant pre-`from_ephemeral` `is_ephemeral` assign
- `state.rs` — `PASSWORD_REDACTED` as `pub(super)` for shared redaction token
- Tests — Debug/Display always-redact; tunnel flags; SSH tunnel without args; RDP+tunnel fail-closed; empty host RDP; HTTPS; double-connect; prepare vs ephemeral field parity
- Docs — `21-quick-connect.md` glue/redaction/non-goals; `16-session-orchestrator.md` QC row + ledger link

## Gate record

### Adversarial loop

| Cycle | Strategy | Accepted findings | Result |
|---|---|---|---|
| Adv-1 | Contract → boundary → state → concurrency → security → integration → tests | QCSC-001…003 | Fixed; reset |
| Adv-2 | Reverse: Debug/Display → empty host → tunnel → protocol → RDP/VNC → double-connect → drift → docs | Docs already aligned post-fix; QCSC-004…007 rejected | Clean (1/2) |
| Adv-3 | Forward on post-fix surface | None | Clean (2/2) |

\* Adv-2 counted clean after docs were verified present; rejected candidates recorded.

### Iterative-review-simplify (after adversarial clean)

| Cycle | Reuse | Efficiency | Quality/Bugs | Accepted | Result |
|---|---|---|---|---|---|
| Sim-1 | Field-parity test re-resolved via hand-rolled HashMap | — | Prefer `QuickConnectState::clone` + `try_build_ephemeral_profile` | Yes → reset | Fixed |
| Sim-2 | QC→tree `options_with_password` merge rejected | No hot-path I/O | No validated bugs | None | Clean (1/3) |
| Sim-3 | Shared redaction const kept; no new abstractions | Same | Diff hygiene / in-scope only | None | Clean (2/3) |
| Sim-4 | Same | Same | No further churn | None | Clean (3/3) |

### Post-simplify adversarial re-run (required)

| Cycle | Strategy | Accepted | Result |
|---|---|---|---|
| Adv-R1 | Delta: clone + ephemeral field-parity test; prior invariants | None | Clean (1/2) |
| Adv-R2 | Reverse: password Debug/Display, tunnel flags, RDP/VNC fail-closed, empty host, double-connect | None | Clean (2/2) |

No further simplify edits after Adv-R*; three consecutive clean simplify cycles remain the last simplify run.

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-ui --lib session_connect
cargo test -p wormhole-ui --lib quick_connect
```

Result: **pass** — `--lib session_connect` **15** ok. Unrelated workspace compile noise in `wormhole-tunnels` / `wormhole-secrets-win` may appear during concurrent edits; scoped QC/session_connect tests green when the workspace compiles.

## Residual notes

- GPUI Quick Connect chrome / transient credential store remain non-goals.
- `connect_quick_connect` does not load tunnel secrets; hosts must set `options.tunnel` before `connect_prepared` when `tunnel_enabled`.
- No HardwarePass / cutover claims.
