# Adversarial ledger — ConnectionEditorState (`wormhole-ui`, no GPUI)

Scope (ONLY):
- `rust/crates/wormhole-ui/src/connection_editor/` (+ focused regressions in `tests/connection_editor_validation.rs`)
- `docs/migration/20-connection-editor.md`

Out of scope: GPUI dialog chrome; Bitwarden / CredMgr I/O; mutating other crates; unrelated `settings_store` / tree / `wormhole-vnc` workspace churn.

Baseline (before review edits): `cargo test -p wormhole-ui --lib --tests` green for connection-editor suite (11 integration tests). Context7 MCP unavailable; domain pins from workspace / `deps-pins.md`.

Docs posture: `20-connection-editor.md` already states **pure Rust state machine (no GPUI)** and lists GPUI dialog chrome as a non-goal — no claim that a GPUI dialog shipped.

## Findings

| ID | Sev | Location | Issue | Evidence | Disposition |
|---|---|---|---|---|---|
| CE-001 | P1 | `state.rs` `ConnectionEditorState` | Derived `Debug` leaked `inline_password` plaintext | `format!("{state:?}")` included secret | **Fixed** — custom `Debug` redacts to `[redacted]`; regression `inline_password_redacted_in_debug` |
| CE-002 | P1 | `http_address.rs` `is_usable_http_host` | Failed `host:port` residues (`10.0.0.1:0`, `fw.local:99999`) accepted as IPv6-ish | Colon + hexdigit/`.` path; C# `Uri.CheckHostName` rejects | **Fixed** — require ≥2 colons for IPv6 branch; matrix + unit coverage |
| CE-003 | P1 | `state.rs` HTTP port fold | Already-bracketed IPv6 (`[fd00::1]`) double-wrapped → `[[fd00::1]]:port` | `host.contains(':')` branch; round-trip broke | **Fixed** — `fold_http_address_port`; regression `http_ipv6_port_fold_does_not_double_bracket` |
| CE-004 | P2 | `tunnel.rs` `to_node_fields` | `enabled=Some(false)` could persist vestigial `config_id` | Hostile field mutation; selection shows NoTunnel | **Fixed** — clear config when enabled is false; `tunnel_no_tunnel_write_clears_vestigial_config_id` |
| CE-005 | P1 | `state.rs` `effective_credential_mode` | QC `Inherit` wrote `CredentialBindingMode::Inherit` | C# collapses QC Inherit → None | **Fixed** — QC Inherit → None; `quick_connect_inherit_credential_collapses_to_none` |
| CE-006 | P2 | `validation.rs` port bounds | HTTP skipped vestigial `port` OOR check | C# `IsValid` uses `!IsSerial` only | **Fixed** — validate `port` for HTTP; matrix asserts `PortOutOfRange` |
| CE-007 | — | Serial COM regex | Require `COM*` shape | C# only blank-host | **Rejected** — parity; HostRequired covers blank |
| CE-008 | — | Clear RDP fields on protocol switch | Stale RDP props on SSH write | C# WriteTo only sets when IsRdp | **Rejected** — intentional parity |
| CE-009 | — | Tunnel `(None, Some(id))` as Config | Looks like Inherit+config | C# TunnelPicker intentional | **Rejected** — domain shape; covered by `tunnel_inherit_null_is_not_false` |
| CE-010 | — | Docs claim GPUI dialog | Attack: overclaim | Status/non-goals say no GPUI | **Rejected** — docs already correct |

## Fixes applied

- Redacted `Debug` for editor state; HTTP host usability rejects port residues; IPv6 address fold without double brackets
- Tunnel write clears config on explicit off; QC credential Inherit → None; HTTP vestigial port bounds
- Regression tests for redaction, HTTP OOR ports, IPv6 fold, tunnel null≠false, serial inherit write-None, QC credentials
- Simplify: `http_default_port`, `fold_http_address_port`, `apply_rdp_drive_list`, `concrete_or_inherit`, collapsed `effective_credential_mode` arms; removed redundant pre-`load_from_node` tunnel tweak

## Gate record

### Adversarial loop

| Cycle | Strategy | Accepted findings | Result |
|---|---|---|---|
| Adv-1 | Contract → boundary → state → security → integration → tests | CE-001…004 | Fixed; reset |
| Adv-2 | Reverse: QC credentials → tunnel null/false → Debug → docs | CE-005 | Fixed; reset |
| Adv-3 | Forward lanes on post-fix; C# `IsValid` port gate | CE-006 | Fixed; reset |
| Adv-4 | Security/logging, Display, docs GPUI, inheritance overwrite | None (CE-007…010 rejected) | Clean (1/2) |
| Adv-5 | Reverse: write_to visibility gates, serial inherit, gateway Always-only | None | Clean (2/2) |

### Iterative-review-simplify (after adversarial clean)

| Cycle | Reuse | Efficiency | Quality/Bugs | Accepted | Result |
|---|---|---|---|---|---|
| Sim-1 | Drive-list + HTTP default helpers; tunnel `set_selection` in profile apply | Drop redundant QC tunnel pre-clear | Credential mode arm merge | Yes → reset | Fixed |
| Sim-2 | `concrete_or_inherit` for serial write | — | — | Yes → reset | Fixed |
| Sim-3 | Further RDP field abstraction — rejected (churn) | No hot-path I/O | No validated bugs | None | Clean (1/3) |
| Sim-4 | Same | Same | Diff hygiene / docs GPUI ok | None | Clean (2/3) |
| Sim-5 | Same | Same | In-scope only | None | Clean (3/3) |

### Post-simplify adversarial re-run (required)

| Cycle | Strategy | Accepted | Result |
|---|---|---|---|
| Adv-R1 | Delta: helpers, `set_selection` profile tunnel, removed pre-clear | None | Clean (1/2) |
| Adv-R2 | Reverse on final connection_editor surface | None | Clean (2/2) |

No further simplify edits after Adv-R*; simplify’s three clean cycles remain the last simplify run.

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-ui --lib --tests
```

Focused equivalent used when unrelated integration tests in the same package are mid-edit by other agents:

```powershell
cargo test -p wormhole-ui --lib --test connection_editor_validation
```

Result: **pass** — lib **74** tests; `connection_editor_validation` **17** tests; `settings_store` **5** tests under `cargo test -p wormhole-ui --lib --tests`. `git diff --check` clean for scoped connection-editor paths.

## Residual notes

- Unrelated package tests (`settings_store`, tree model mid-refactor) may fail transiently under parallel agents; connection-editor surface is green in isolation.
- GPUI dialog binding remains a non-goal; this ledger does not claim UI chrome shipped.
