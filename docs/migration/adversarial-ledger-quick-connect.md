# Adversarial ledger — Quick Connect (`wormhole-ui`)

Scope (ONLY):
- `rust/crates/wormhole-ui/src/quick_connect/`
- Related editor validation used by QC (`connection_editor/validation.rs` port-box skip)
- `docs/migration/21-quick-connect.md`, README ledger link

Out of scope: GPUI chrome wiring; transient credential store / tab factory; C# production app; unrelated `settings_store` / tree / VNC workspace noise.

Baseline: `cargo test -p wormhole-ui --lib quick_connect` (19→25 tests through review). Context7 MCP unavailable; pins from workspace `Cargo.toml` / `deps-pins.md`.

## Findings

| ID | Sev | Location | Issue | Evidence | Disposition |
|---|---|---|---|---|---|
| QC-001 | P1 | `validation.rs` port check | HTTP(S) still applied `PortOutOfRange` to hidden port box (stale SSH `port=0` blocked Connect) | Switch SSH→HTTP with `port=0` | **Fixed** — skip port range when `is_http` (same as serial); QC `set_protocol` clears port for Serial/HTTP/HTTPS |
| QC-002 | P2 | `QuickConnectState::try_build` / `tunnel_selection` | `editor_mut` Inherit-shaped tunnel (`enabled=None` + vestigial `config_id`) could write `tunnel_enabled=None` + leftover config id | Tamper then accept | **Fixed** — getter treats `enabled.is_none()` as NoTunnel; `try_build` forces `allow_inheritance=false` and re-applies QC selection |
| QC-003 | P2 | Host rules / blank name | Serial `\\.\COM10`, HTTP IP, whitespace name→host, HTTPS blank name→parsed bare host under-tested | Attack lanes | **Fixed** — focused regressions |
| QC-004 | P2 | Docs / ledger | Port/host rules under-documented; ledger + README link missing | Feature-matrix / policy | **Fixed** — `21-quick-connect.md`, `20-connection-editor.md`, README, this ledger |
| QC-005 | P3 | Debug/Display | Password must not appear in `Debug`/`Display` (C# `DebuggerBrowsable` / `ToString`) | `format!("{result:?}")` / `format!("{result}")` | **Fixed** (pre-existing Debug + Display) + state Debug + Display regressions |
| QC-006 | — | COM format gate | Require `COM*` shape for Serial | C# accepts any non-blank Host | **Rejected** — C# parity; no format gate |
| QC-007 | — | Privatize `password` field | Prevent `{:?}` on destructured field | C# public get | **Rejected** — pub field matches C#; Debug/Display redact |
| QC-008 | — | Restore password if resolve fails | `try_build` takes password before resolve | Solo validated node cannot hit `ResolveError` | **Rejected** — unreachable for valid QC accept |
| QC-009 | — | Duplicate `default_port` vs domain | Drift risk | Public QC table mirrors resolver | **Rejected** — intentional public helper; covered by ephemeral default-port test |

## Fixes applied

- Shared validation: ignore network port range for HTTP(S); QC clears stale port on protocol switch
- Tunnel: QC getter/setter never surface Inherit; accept path normalizes before write
- Host/name regressions: serial extended COM, HTTP IP, whitespace/HTTP blank name, stale-port switch, VNC ephemeral out-of-band password
- Docs + ledger + README link; no GPUI readiness claim

## Gate record

### Adversarial loop

| Cycle | Strategy | Accepted findings | Result |
|---|---|---|---|
| Adv-1 | Contract → boundary → state → security → integration → tests | QC-001…005 | Fixed; reset |
| Adv-2 | Reverse: Debug → host rules → InheritanceResolver ephemeral → validation wrap → docs | QC-005 test harden; ledger | Fixed; reset |
| Adv-3 | Forward on post-fix surface | None | Clean (1/2) |
| Adv-4 | Reverse: secrets, serial/IP, ephemeral flag, tunnel tamper, GPUI claim | None | Clean (2/2) |

### Iterative-review-simplify (after adversarial clean)

| Cycle | Reuse | Efficiency | Quality/Bugs | Accepted | Result |
|---|---|---|---|---|---|
| Sim-1 | Merge credential-less + port-clear `matches` in `set_protocol` | Avoid `node.clone()` in ephemeral HashMap | — | Yes → reset | Fixed |
| Sim-2 | Collapse try_build tunnel normalize to getter+setter | — | Drop dead Inherit match in `tunnel_selection` | Yes → reset | Fixed |
| Sim-3 | Fold serial/`enabled.is_none()` early return | No hot-path I/O | No validated bugs | Yes → reset | Fixed |
| Sim-4 | Same | Same | Diff hygiene ok | None | Clean (1/3) |
| Sim-5 | Same | Same | In-scope only | None | Clean (2/3) |
| Sim-6 | Same | Same | No further churn | None | Clean (3/3) |

### Post-simplify adversarial re-run (required)

| Cycle | Strategy | Accepted | Result |
|---|---|---|---|
| Adv-R1 | Delta: tunnel normalize, selection fold, set_protocol merge, no-clone resolve | None | Clean (1/2) |
| Adv-R2 | Reverse on final surface (password, host rules, ephemeral, docs) | None | Clean (2/2) |

No further simplify edits after Adv-R*; simplify’s three clean cycles remain the last simplify run.

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-ui --lib quick_connect
cargo test -p wormhole-ui --test connection_editor_validation
# Broader suite may hit unrelated settings_store / tree noise — ignore per brief.
```

Result: **pass** — `--lib quick_connect` **25** ok; `connection_editor_validation` **17** ok. `git diff --check` clean for scoped paths. Unrelated: `settings_store` / intermittent tree compile noise outside this scope.

## Residual notes

- GPUI Quick Connect chrome remains a non-goal (title-bar stub only).
- Transient credential store / tab open path stay in the host app (C# today).
