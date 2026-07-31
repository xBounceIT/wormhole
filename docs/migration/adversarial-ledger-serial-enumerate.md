# Adversarial ledger — serial port enumeration

**Scope:** `rust/crates/wormhole-serial/` (`enumerate.rs` / `SerialPortEnumerator` / `list_serial_ports*`), related settings open-path validation, `docs/migration/README.md` serial note  
**Date:** 2026-07-31  
**Gates:** 2 clean adversarial cycles + 3 clean iterative-review-simplify cycles (post-fix; adversarial renewed after simplify edit)

## Baseline

- `cargo test -p wormhole-serial` green (19 tests) before review.
- Attack focus: Fake/Memory deterministic; system soft-fail; COM path sanitization; Windows/`cfg(not(windows))`; no real COM hardware in tests; docs must not claim product UI COM picker shipped; preserve `SerialSession` tests.

## Findings

| ID | Sev | Location | Issue | Evidence | Disposition |
|---|---|---|---|---|---|
| SE-001 | P1 | `enumerate.rs` `list_serial_ports_system` | OS/`available_ports` errors propagated; picker could hard-fail on SetupDi/permission issues | Attack focus requires soft-fail; known serialport Win failures | **Fixed** — `soft_fail_system_port_names` maps `Err` → `[]` |
| SE-002 | P1 | settings / `open_builder` | Hostile Host / Fake strings (`\\.\pipe\…`, drive paths, `..\`) reached `tokio_serial::new` / CreateFile with only non-empty check | No COM-shape validation | **Fixed** — `normalize_serial_port_name` at `from_optional` / `from_profile` / `open_builder` |
| SE-003 | P2 | `docs/migration/README.md` | Wording implied connection editor / Quick Connect COM picker already shipped | README sentence | **Fixed** — library API + explicit “picker not shipped” |
| SE-004 | P2 | `enumerate` tests | Soft-fail / hostile-name / determinism contracts unpinned; `system_list` only discarded `Result` | Missing negative/oracle tests | **Fixed** — soft-fail, filter, normalize, determinism, Fake-hostile regressions |
| SE-005 | P2 | system list filter | Valid-but-messy OS names kept raw (`com7:`) instead of canonical | Filter used `is_valid` only | **Fixed** — `filter_map(normalize…)` |
| SE-006 | P2 | `normalize_serial_port_name` | Oversized digit / Host payloads accepted after numeric parse | Boundary lane | **Fixed** — max 32 chars; digit run ≤ 3 |
| SE-007 | P3 | `session` test | `COM_DOES_NOT_EXIST_…` became invalid under new validator | Would fail `from_optional` before OS open | **Fixed** — use valid-shaped `COM199` |
| SE-R1 | — | Fake leaves hostile names unsanitized | By design for deterministic test injection; open validates | Attack focus | **Rejected** — intentional split |
| SE-R2 | — | System vs Fake error asymmetry | System soft-fails; Fake `failing()` returns `Err` | Error-path UI tests | **Rejected** — documented |
| SE-R3 | — | Dedupe/sort system ports | Not required | Taste | **Rejected** |
| SE-R4 | — | `open_missing_port_fails` if COM199 exists | Extremely unlikely hardware collision | Residual | **Rejected** — residual |

## Fixes applied

- `src/enumerate.rs` — soft-fail system list; normalize/validate COM names; Memory/Fake docs; regression tests
- `src/settings.rs` — normalize on profile/optional; re-validate in `open_builder`
- `src/lib.rs` — export `normalize_serial_port_name` / `is_valid_windows_com_port_name`
- `src/session.rs` — missing-port test uses `COM199`
- `docs/migration/README.md` — ledger link + non-shipping picker wording

## Gate record

### Adversarial loop (post-fix; renewed after simplify)

| Cycle | Strategy | Accepted findings | Result |
|---|---|---|---|
| Adv-1 | Contract → boundary → state → concurrency → security → integration → perf → tests | None (after SE-001…007) | Clean (1/2) |
| Adv-2 | Reverse: tests-as-oracles → security/injection → cfg stubs → Fake vs System contracts | None | Clean (2/2) |

### Iterative-review-simplify

| Cycle | Reuse | Efficiency | Quality/Bugs | Accepted | Result |
|---|---|---|---|---|---|
| Sim-1 | Empty-name checks already centralized in `normalize` | Enumeration is tiny | Unreachable `parse` `map_err` → `unwrap_or(0)` + range | **Fixed** (reset counters; adversarial re-run) | Then clean after renew |
| Sim-1b | Public `is_valid_*` thin wrapper kept for API/tests | No hot-path I/O | Caps + dual open validation retained | None | Clean (1/3) |
| Sim-2 | No missed helpers worth extracting | Memory clone-per-list intentional | Digit/len caps consistent with tests | None | Clean (2/3) |
| Sim-3 | Exports match call sites | Soft-fail helper testable without hardware | Docs/ledger aligned; session tests green | None | Clean (3/3) |

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-serial
```

**Result (final):** 28 passed (enumerate + settings + session); 0 failed.

## Gate confirmation

- Adversarial clean passes: **2** (independent orderings; renewed after simplify edit).
- Iterative-review-simplify clean passes: **3**.
- No accepted non-blocked findings remain.
