# Adversarial ledger — RDP performance flags / bitmap-cache Fake configure glue

Scope: `rust/crates/wormhole-surface-win/src/rdp/performance_flags_glue.rs` (+ `rdp/mod.rs` exports), `docs/migration/05-rdp-spike.md` performance/bitmap notes, feature-matrix / interop / README index  
Out of scope: CredSSP wipe rewrite; display/redirect Fake rewrite; live OCX / `mstscax`; audio / keyboard-hook / NetworkConnectionType / AutoReconnect  
Baseline: `cargo test -p wormhole-surface-win --features rdp` green  
Design SoT: C# `RdpHostForm.BuildPerformanceFlags` + `TrySetOptional` for `PerformanceFlags` / `BitmapCachePersistEnable` / `BitmapPeristence`

## Findings

| ID | Sev | Location | Issue | Evidence | Disposition |
|---|---|---|---|---|---|
| PF-001 | P2 | tests | All-soft-miss + attempted report values unpinned | Soft TrySet must stay `Ok`; report fields are attempted | **Fixed** — `all_soft_miss_still_ok_with_attempted_report_values` |
| PF-002 | P2 | Fake / docs | Re-apply accumulates records; callers need `clear_records` | Sister Fake contract; easy to misread as replace | **Fixed** — `reapply_appends_records_unless_cleared` + spike note |
| PF-003 | P3 | `05-rdp-spike.md` display section | Still said “not audio/performance” after perf glue landed | Doc drift | **Fixed** — display section points at separate perf Fake |
| PF-004 | P3 | `interop-inventory.md` | Performance flags listed without Fake glue pointer | Inventory lag | **Fixed** — pointer to spike |
| PF-005 | — | Merge Fake with `FakeRdpPropertySurface` | DRY across glues | Would rewrite display_redirect | **Rejected** — user gate; sister Fake |
| PF-006 | — | Include audio / keyboard / NetworkConnectionType / AutoReconnect | Adjacent C# Configure lines | Out of scope | **Rejected** |
| PF-007 | — | Drop `Result` / `PerformanceFlagsGlueError` (never Err) | Dead Err path | Sister API parity + reserved fail-closed | **Rejected** |
| PF-008 | — | CredSSP / display_redirect rewrite | User gate | Out of scope | **Rejected** |
| PF-009 | — | Hex Fake values for `PerformanceFlags` | Taste | Decimal `u32::to_string` is fine | **Rejected** |

## Fixes applied

- `rdp/performance_flags_glue.rs` — `build_performance_flags` + Fake TrySet glue; attack-focus regressions (all soft-miss, re-apply clear contract); single `record_soft` path after simplify
- `rdp/mod.rs` / `lib.rs` / `Cargo.toml` — exports + feature comments
- `docs/migration/05-rdp-spike.md` — works row, deferred row, performance section, module table
- `docs/migration/feature-matrix.md`, `interop-inventory.md`, `README.md` — status / ledger index
- `wormhole-domain/Cargo.toml` — enable `uuid` `v4` on lib dep (unblock `clone_as_new_identity` so `--features rdp` compiles)

## Gate record

### Adversarial loop

| Cycle | Strategy | Accepted findings | Result |
|---|---|---|---|
| Adv-0 | Contract → boundary → state → concurrency → security → integration → perf → tests | PF-001…004 | Fixed; counter reset |
| Adv-1a | Same lanes on fixed tree; C# `BuildPerformanceFlags` bit packing | None | Clean (1/2) |
| Adv-1b | Reverse: tests-as-oracles → legacy `BitmapPeristence` independence → no OCX/CredSSP/display rewrite → PF-005…009 hold | None | Clean (2/2) |
| Adv-2a (post-simplify) | Delta: single `record_soft` / removed typed try_put_* | None | Clean (1/2) |
| Adv-2b (post-simplify) | Reverse: C# order + bool/`0`/`1` string values + soft-miss independence | None | Clean (2/2) |

### Iterative-review-simplify (after adversarial clean)

| Cycle | Reuse | Efficiency | Quality/Bugs | Accepted | Result |
|---|---|---|---|---|---|
| Sim-1 | Reject Fake merge with display (PF-005) | Collapse typed `record_soft_*` / `try_put_*` → one `record_soft` | Soft-miss + legacy independence pins intact | Collapse helpers | Fixed; counter reset |
| Sim-2 | Exports via `rdp/mod.rs` only; spike table matches | No I/O; Fake `Vec` only | Attempted report values + re-apply clear contract | None | Clean (1/3) |
| Sim-3 | Keep `Result` Err type (PF-007); keep separate Fake | Reject hex Fake (PF-009) | PF-006/008 remain rejected | None | Clean (2/3) |
| Sim-4 | Catalog / const bit names match C# | No hot-path churn | Docs attempted-value note matches code | None | Clean (3/3) |

After Sim-1 edit → adversarial re-loop Adv-2a/2b clean → Sim-2…4 clean.

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-surface-win --features rdp
```

Result: **pass** — performance_flags unit tests (14) + full crate with `--features rdp` (190).

## Residual

- Live OCX apply of performance/bitmap Fake puts remains deferred (`05-rdp-spike.md`).
- Audio / keyboard-hook / `NetworkConnectionType` / `EnableAutoReconnect` stay deferred.
- CredSSP wipe and display/redirect Fake glues unchanged (separate ledgers).
