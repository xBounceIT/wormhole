# Adversarial ledger — SerialPortPickerState host-field glue

**Scope:** `rust/crates/wormhole-ui/src/serial_ports.rs` (`SerialPortPickerState` / `list_ports_fail_closed` / refresh / `select_into_editor` / `select_into_quick_connect`), docs notes in `20-connection-editor.md`, `21-quick-connect.md`, `feature-matrix.md`, `README.md`  
**Date:** 2026-07-31  
**Gates:** 2 clean adversarial cycles + 3 clean iterative-review-simplify cycles

## Baseline

- `cargo test -p wormhole-ui --lib serial_ports` green (8 tests) before review.
- `cargo test -p wormhole-serial` green (28 tests).
- Attack focus: fail-closed enumerator `Err`, empty list, OOB select; Host writes only when protocol is Serial; no live `SerialPort` open; Fake-only in tests; docs must not claim GPUI COM combo shipped.
- Preserve unrelated `wormhole-ui` / migration work.

## Findings

| ID | Sev | Location | Issue | Evidence | Disposition |
|---|---|---|---|---|---|
| SP-001 | P2 | `serial_ports.rs` `select_into_quick_connect` | Duplicated get/clone path vs `select_into_editor` / `select_into_host` — drift risk on protocol/OOB rules | Parallel implementations; QC embeds `ConnectionEditorState` | **Fixed** — delegate to `select_into_editor(qc.editor_mut())` |
| SP-002 | P2 | `serial_ports` tests | Recovery after `Err` refresh and editor OOB on populated list unpinned | Only empty-picker / QC OOB covered | **Fixed** — `refresh_ok_after_fail_*` + `select_after_failed_refresh_and_oob_*` |
| SP-003 | P2 | module docs / `20` / `21` / README | `refresh_failed` vs System soft-fail (`Ok([])`) undocumented; ledger / index missing | Product OS errors never set `refresh_failed` (enumerate SE-R2) | **Fixed** — docs + ledger + README index row |
| SP-R1 | — | Normalize / sanitize on select | Fake may inject hostile names into Host | Open path validates via `normalize_serial_port_name`; enumerate Fake split intentional | **Rejected** — same as SE-R1 |
| SP-R2 | — | Clear Host on failed refresh | Stale COM could remain in Host after list clear | Manual Host edit must survive refresh fail | **Rejected** — fail-closed applies to list/select, not Host wipe |
| SP-R3 | — | Case-insensitive `select_named_into_host` | Exact match only | Index select is primary; no GPUI yet | **Rejected** — not in acceptance criteria |
| SP-R4 | — | Protocol-gated named select into editor/QC | Only raw `select_named_into_host` | Lower-level host helper by design | **Rejected** |
| SP-R5 | — | `list_ports_fail_closed` has no fail flag | Empty for both `Ok([])` and `Err` | Documented; use picker `refresh` for flag | **Rejected** — by design |

## Fixes applied

- `serial_ports.rs` — QC select delegates to editor; System soft-fail / `refresh_failed` docs; recovery + OOB regression tests
- `docs/migration/20-connection-editor.md` — refresh semantics table + ledger link
- `docs/migration/21-quick-connect.md` — soft-fail note + ledger link
- `docs/migration/README.md` — index row + UI glue wording
- `docs/migration/adversarial-ledger-serial-picker.md` — this ledger

## Gate record

### Adversarial loop

| Cycle | Strategy | Accepted findings | Result |
|---|---|---|---|
| Adv-0 | Contract → boundary → state → concurrency → security → integration → perf → tests | SP-001…003 | Fixed; reset |
| Adv-1 | Same order on updated impl | None | Clean (1/2) |
| Adv-2 | Reverse: tests-as-oracles → security → integration → state → contract | None | Clean (2/2) |

### Iterative-review-simplify

| Cycle | Reuse | Efficiency | Quality/Bugs | Accepted | Result |
|---|---|---|---|---|---|
| Sim-1 | QC→editor delegation; no further helpers worth extracting | COM list clones tiny | Docs/tests aligned with fail-closed | None | Clean (1/3) |
| Sim-2 | `list_ports_fail_closed` kept separate (no Err flag) | Named-select double scan rejected as micro | Invariants: Err clears list; Ok clears flag | None | Clean (2/3) |
| Sim-3 | Exports match `lib.rs`; docs/feature-matrix Pending chrome | No I/O / no live port | Ledger + verification commands | None | Clean (3/3) |

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-ui --lib serial_ports
cargo test -p wormhole-serial
```

**Result (final):** `serial_ports` 10 passed; `wormhole-serial` 28 passed; 0 failed.

## Gate confirmation

- Adversarial clean passes: **2** (independent orderings).
- Iterative-review-simplify clean passes: **3**.
- No accepted non-blocked findings remain.
- No live `SerialPort` / hardware in tests.
