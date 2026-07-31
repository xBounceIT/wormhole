# Adversarial ledger — Serial baud / parity preset VM glue

**Scope:** `rust/crates/wormhole-serial/src/presets.rs` (`SerialLineCombo` / catalogs / DCB `validate_serial_combo` / node apply), `rust/crates/wormhole-serial/src/settings.rs` (open-path DCB after normalize), `rust/crates/wormhole-ui/src/serial_presets.rs` (editor/QC mapping), `connection_editor/validation.rs` + `state.rs::write_to`, `quick_connect/state.rs` serial setters, docs in `20-connection-editor.md` / `feature-matrix.md` / `README.md`  
**Date:** 2026-07-31  
**Gates:** 2 clean adversarial cycles + 3 clean iterative-review-simplify cycles  
**Impl:** `3adeff2e-f9ea-4ecd-bca6-17e2a78a8646`  
**Constraints:** No child agents; no HardwarePass / live `SerialPort` in tests.

## Baseline

- `cargo test -p wormhole-serial` green (37 → 38 after open-path DCB test).
- `cargo test -p wormhole-ui --lib serial_presets` green (10 → 13 after regression tests).
- Attack focus: defaults **9600 8N1, flow None**; fail-closed illegal Win32 DCB (1.5 stop only with 5 data bits; 2 stop invalid with 5 data bits); OOB preset index; non-Serial protocol; editor/QC/save/open integration drift.
- Preserve unrelated migration / crate work.

## Findings

| ID | Sev | Location | Issue | Evidence | Disposition |
|---|---|---|---|---|---|
| SPP-001 | P1 | `connection_editor/validation.rs` + `state.rs::write_to` | Editor save path did not enforce DCB; `to_connection_node` / persist could write 8+1.5 | `is_valid()` only checked baud/data range; serial write used raw `concrete_or_inherit` | **Fixed** — `SerialStopDataComboInvalid`; `write_to` routes through `write_editor_serial_to_node` |
| SPP-002 | P1 | `wormhole-serial` `settings.rs` `from_*` | Open path normalized but did not validate stop/data pairing | Tests previously accepted 7/8 + 1.5 | **Fixed** — `validate_serial_combo` after normalize; regression test |
| SPP-003 | P2 | `write_to` + illegal combo | In-place write left stale prior `serial_*` when glue returned false | `write_editor_serial_to_node` no-mutates on Err | **Fixed** — clear `serial_*` on illegal write |
| SPP-004 | P2 | `quick_connect/state.rs` `set_serial_*` | QC setters planted illegal DCB; bypassed preset fail-closed | Direct field assigns; `serial_baud_invalid_rejected` relied on mutating to 0 | **Fixed** — delegate to `set_custom_*`; update baud test |
| SPP-005 | P2 | docs / ledger | Validation matrix omitted DCB; ledger + README index missing | Gate policy requires ledger | **Fixed** — matrix row, ledger, README index |
| SPP-006 | P2 | `serial_presets` tests | Illegal `write_editor_serial_to_node` / `write_to` stale clear unpinned | Only select/load fail-closed covered | **Fixed** — focused regression tests |
| SPP-R1 | — | Mixed inherit data/stop | Partial override can store stop=1.5 with data=`None` | Documented: validate display; all-inherit skips | **Rejected** — folder resolve out of scope; matches documented inherit rule |
| SPP-R2 | — | `load_from` vs `load_node_serial_into_editor` | Editor load normalizes illegal pairs; glue fail-closes | Dual API intentional (C# load parity vs strict glue) | **Rejected** |
| SPP-R3 | — | Hand-built `SerialLineSettings` | Could bypass `from_*` validate | Primary constructors + session path use `from_*` | **Rejected** — advanced construct; not product path |
| SPP-R4 | — | Missing `set_custom_baud_qc` export | QC has setters; preset module has index QC wrappers | Not required by acceptance | **Rejected** |

## Fixes applied

- `presets.rs` — keep catalogs / DCB validate; drop dead parity/flow binds in `validate`
- `settings.rs` — DCB validate after normalize; fix illegal 1.5 test fixtures to data bits 5
- `serial_presets.rs` — `set_custom_data_bits` / `set_custom_stop_bits` / `editor_serial_all_inherit`; select_* delegates; write/load glue
- `validation.rs` — `SerialStopDataComboInvalid` via shared all-inherit helper
- `state.rs` — serial `write_to` through glue; clear stale on illegal
- `quick_connect/state.rs` — fail-closed serial setters
- Docs: `20-connection-editor.md`, `README.md`, this ledger

## Gate record

### Adversarial loop

| Cycle | Strategy | Accepted findings | Result |
|---|---|---|---|
| Adv-0 | Contract → boundary → state → concurrency → security → integration → perf → tests | SPP-001…006 | Fixed; reset |
| Adv-0b | Same after QC/write_to fixes | (none new beyond simplify later) | — |
| Adv-1 | Post-fix full lanes | None | Clean (1/2) |
| Adv-2 | Reverse: tests-as-oracles → security → integration → state → contract | None | Clean (2/2) |
| Adv-R1 | After simplify delta (reuse helpers / from_profile) | None | Clean (1/2) |
| Adv-R2 | Reverse on simplify delta | None | Clean (2/2) |

### Iterative-review-simplify

| Cycle | Reuse | Efficiency | Quality/Bugs | Accepted | Result |
|---|---|---|---|---|---|
| Sim-1 | Extract `set_custom_data/stop_bits`; select_* + QC delegate; `editor_serial_all_inherit` shared | `from_profile` avoid host clone | Dead `concrete_or_inherit` removed earlier | Yes → reset | Fixed |
| Sim-2 | Exports in `lib.rs` aligned | No hot-path I/O | Invariants: OOB→false then set_custom; all-inherit skip consistent | None | Clean (1/3) |
| Sim-3 | No further helpers worth extracting | Catalog lookups O(n) tiny | Ledger/docs/tests pin fail-closed | None | Clean (2/3) |
| Sim-4 | Same scope re-read | — | No HardwarePass; dual load API kept | None | Clean (3/3) |

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-serial
cargo test -p wormhole-ui --lib serial_presets
```

**Result (final):** `wormhole-serial` 38 passed; `serial_presets` 13 passed; related QC/validation serial tests green; 0 failed.

## Gate confirmation

- Adversarial clean passes: **2** (independent orderings; re-confirmed after simplify).
- Iterative-review-simplify clean passes: **3**.
- No accepted non-blocked findings remain.
- No live `SerialPort` / HardwarePass in tests.
