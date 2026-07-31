# Adversarial ledger — `wormhole-domain`

Scope: `rust/crates/wormhole-domain/`, `docs/migration/02-domain.md`  
Baseline: `cargo test -p wormhole-domain` green (57 tests) before review  
C# SoT: `Data/InheritanceResolver.cs`, `Wormhole.Tests/Data/InheritanceResolver*.cs`

## Findings

| ID | Sev | Location | Issue | Evidence | Disposition |
|---|---|---|---|---|---|
| D-DOMAIN-001 | P2 | `src/enums.rs` | No `TryFrom<i32>` / `as_i32` → storage could invent divergent SQLite maps; retired protocol `2` unenforced | Acceptance: enum numerics must match C#; no round-trip API | **Fixed** — `as_i32` + `TryFrom<i32>` (`InvalidEnumValue`); rejects `ProtocolType` 2 |
| D-DOMAIN-002 | P2 | tests | Attack-focus edge cases unpinned (whitespace host, missing parent, empty map, self-cycle, Unicode, protocol-agnostic port, Inherit ignores own cred id, Saved+null cred, tunnel leaf true over folder false, disabled keeps config id) | Probes passed on impl; tests missing | **Fixed** — regression tests in inheritance + tunnel suites |
| D-DOMAIN-003 | P2 | tests | Discriminants / helpers / GUID D / sentinels / SerialDefaults / RdpScreenSizes untested | `cargo test` had 0 lib unit tests for these contracts | **Fixed** — `enum_parity_tests.rs`, `domain_helpers_tests.rs` |
| D-DOMAIN-004 | P3 | `docs/migration/02-domain.md` | Stale uuid pin `1.17.0` vs workspace `1.24.0` | Cargo.toml workspace.dependencies | **Fixed** — doc pin + TryFrom note |
| D-DOMAIN-005 | P3 | `src/error.rs` | `NotAConnection` used `{:?}` for `NodeKind` | Cosmetics vs C# `ToString()` | **Fixed** — `Display` on `NodeKind` + `{kind}` |
| D-DOMAIN-006 | — | serial tunnel force-off | Suspected missing coverage | Already asserted in `resolve_serial_inherits_serial_settings_and_drops_credentials` | **Rejected** — covered |
| D-DOMAIN-007 | — | inheritance logic bugs | Hostile probes (serial tunnel, whitespace host, cycles, unicode, agnostic port, inherit cred) | All matched C# behavior | **Rejected** — no reachable defect |
| D-DOMAIN-008 | — | secret logging | Password / PendingInlinePassword exposure | Domain has no secret payload fields; no logging APIs | **Rejected** — clean |

## Fixes applied

- `src/enums.rs` — `as_i32`, `TryFrom<i32>`, `Display` where useful
- `src/error.rs` — `InvalidEnumValue`; NodeKind Display in errors
- `src/serial.rs` — simplify enum normalizers to `unwrap_or` (invalid wire values gated by `TryFrom`)
- `src/lib.rs` — export `InvalidEnumValue`
- Tests — enum/helpers + inheritance/tunnel edge cases
- `docs/migration/02-domain.md` — pin + API + test notes
- Removed temporary `examples/adv_probe.rs`

## Gate record

### Adversarial loop (post-fix)

| Cycle | Strategy | Accepted findings | Result |
|---|---|---|---|
| Adv-1 | Contract → boundary → state → concurrency → security → integration → perf → tests | None | Clean (1/2) |
| Adv-2 | Reverse: tests-as-oracles → security/PII → enum wire map → C# walk parity spot-check | None | Clean (2/2) |

### Iterative-review-simplify (after adversarial clean)

| Cycle | Reuse | Efficiency | Quality/Bugs | Accepted | Result |
|---|---|---|---|---|---|
| Sim-1 | Inheritance field `or`/`or_else` mirrors C#; no extract | Separate `find_resolved_protocol` matches C#; keep | Serial `unwrap_or` already done; trivial `eq_ignore_ascii_case` wrapper not worth churn | None | Clean (1/3) |
| Sim-2 | Test helpers duplicated lightly across files — reject shared testkit for 3 lines | No hot-path I/O | Display/TryFrom consistent; no secret fields | None | Clean (2/3) |
| Sim-3 | No missed local helpers | Clone-on-walk same as C# | Docs/tests aligned with impl; diff in-scope | None | Clean (3/3) |

No simplify edits → adversarial remain 2/2 clean (no reset).

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-domain
```

Result: **pass** (73 tests: 61 inheritance + 5 tunnel + 3 enum + 4 helpers).
