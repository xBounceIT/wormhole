# Adversarial ledger — RDP external mstsc Fake policy glue

Scope: `rust/crates/wormhole-surface-win/src/rdp/external_mstsc_glue.rs` (+ `rdp/mod.rs`
exports), docs in `docs/migration/05-rdp-spike.md` external-mstsc section + README link  
Out of scope: CredSSP wipe; display/redirect / performance Fake rewrites; live
`mstsc.exe` / `Process::Command`; C# `ShouldUseExternalClientAsync` AAD auto-detect;
`wormhole-session` surface-win dependency  
Constraints / attack focus:
- `tunnel_enabled && use_external_client` → `RejectWhenTunnelEnabled` + C# message
- Tunnel off + external → `AllowExternalMstsc` (Fake `launch_eligible_count` only)
- Message identity with `TUNNEL_EXTERNAL_CLIENT_UNSUPPORTED` / C# constant
- Focused decision matches `validate_tunnel_rdp_policy` ExternalClient arm
- No process spawn; Fake counters only  
Baseline: `cargo test -p wormhole-surface-win --features rdp` green before review  
Design SoT: `docs/migration/05-rdp-spike.md`, C# `RdpSessionViewModel.ConnectAsync`
external branch; policy parent `configure.rs` + [adversarial-ledger-rdp-external.md](adversarial-ledger-rdp-external.md)

## Findings

| ID | Sev | Location | Issue | Evidence | Disposition |
|---|---|---|---|---|---|
| EM-001 | P2 | (missing) | No callable Fake API despite solid `configure.rs` policy | Task requires `AllowExternalMstsc` vs `RejectWhenTunnelEnabled` glue + tests | **Fixed** — `external_mstsc_glue.rs` + exports |
| EM-002 | P2 | glue | `evaluate_external_route` could imply live launch | Attack: accidental `Command` spawn | **Fixed** — Fake counters only; `glue_does_not_spawn_process_on_allow` contract test |
| EM-003 | P2 | tests | Reject path message not pinned to C# literal independently | Same oracle gap as EX-001 in configure | **Fixed** — `CSHARP_TUNNEL_EXTERNAL_CLIENT_UNSUPPORTED` in glue tests |
| EM-004 | P3 | glue | Decision could drift from `validate_tunnel_rdp_policy` External arm | Duplicate policy sources | **Fixed** — `external_decision_matches_tunnel_policy` identity helper + test |
| EM-005 | P3 | `record_evaluate` | Reject must not bump `launch_eligible_count` | Host-network bypass must not look launch-ready | **Fixed** — `glue_fake_records_reject_without_launch_eligible` |
| EM-006 | — | Duplicate full `TunnelRdpPolicy` in glue | Gateway/strict already in configure | External glue is bool-only; gateway/strict stay separate C# guards | **Rejected** — focused scope |
| EM-007 | — | Wire AAD into glue | Needs credential catalog | Deferred per EX-003 / configure parent ledger | **Rejected** — effective bool input |
| EM-008 | — | `wormhole-session` dep on surface-win | COM/OLE crate in session stubs | Session RDP still `UnsupportedProtocol` | **Rejected** — keep deferred |
| EM-009 | — | CredSSP / performance / display rewrite | User gate | Out of scope | **Rejected** |

## Fixes applied

- `rdp/external_mstsc_glue.rs` — `ExternalMstscTunnelDecision`, `decide_external_mstsc_tunnel`,
  `validate_external_mstsc_tunnel`, `RdpExternalMstscGlue` / `FakeExternalMstscSurface`, identity helper
- `rdp/mod.rs` / `lib.rs` — exports + feature comment
- `docs/migration/05-rdp-spike.md` — works row, external-mstsc section, module table, re-audit pin
- `docs/migration/README.md` — ledger link
- `docs/migration/adversarial-ledger-rdp-external-mstsc.md` — this ledger

## Gate record

### Adversarial loop

| Cycle | Strategy | Accepted findings | Result |
|---|---|---|---|
| Adv-0 | Contract → boundary → no spawn → message identity → policy delegation → session/AAD deferred | EM-001…005 | Fixed (new module) |
| Adv-1 | Reverse: C# string byte-match; reject skips launch_eligible; configure External arm identity; no Command | None | Clean (1/2) |
| Adv-2 | Tests-as-oracles → docs pin → reject EM-006…009 → CredSSP/display/perf untouched | None | Clean (2/2) |

### Iterative-review-simplify

| Cycle | Reuse | Efficiency | Quality/Bugs | Accepted | Result |
|---|---|---|---|---|---|
| Sim-1 | Delegate message to `TUNNEL_EXTERNAL_CLIENT_UNSUPPORTED` const | Pure bool; no I/O | Reject duplicate full policy struct in glue API | None | Clean (1/3) |
| Sim-2 | Single `decide` + `validate` (minor double-call in evaluate — acceptable) | Fake `Vec`-less counters only | launch_eligible only on Allow | None | Clean (2/3) |
| Sim-3 | Exports via `rdp/mod.rs`; spike table matches | No hot-path work | EM-006…009 remain rejected | None | Clean (3/3) |

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-surface-win --features rdp -- external_mstsc
```

Result: **pass** — 10 unit tests in `external_mstsc_glue.rs` + full crate with `--features rdp`.

## Residual notes

- C# `ShouldUseExternalClientAsync` AAD auto-detect is implemented in
  `aad_external_client_glue.rs` (`RdpAadExternalClientGlue`); this glue still takes effective
  `use_external_client` when invoked directly.
- Live `mstsc.exe` launch / crash-sentinel auto-flag remain deferred (no `Process::Command` in tests or glue).
- Gateway / strict tunnel rejects stay in `configure.rs` / `prepare_rdp_connect_target` — not duplicated in this glue.
- CredSSP / display / performance Fake glues unchanged.
