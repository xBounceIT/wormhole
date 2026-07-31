# Adversarial ledger — SettingsViewModel → StorageSettingsStore apply glue

**Scope:** `rust/crates/wormhole-ui/src/settings/` — `StorageSettingsStore`, `SettingsViewModel` stage/apply/reload/save, UI `AppSettings` unknown-field retention; docs `03-storage.md` / `17-tree-settings-vm.md`; `settings::*` tests under `--features storage`.  
**Authority:** full adversarial-review-fix (edit in scope; do not stop at findings).  
**Baseline:** `cargo test -p wormhole-ui --features storage --lib settings::` green before review edits. Context7 MCP unavailable; pins from workspace / `deps-pins.md`.  
**Out of scope:** HardwarePass / cutover; GPUI chrome; dual-write with `JsonFileSettingsStore`; unrelated `wormhole-tunnels` churn.

## Gate status

| Gate | Result |
|---|---|
| Adversarial clean passes | **2** consecutive (post-fix + post-simplify re-run) |
| iterative-review-simplify clean passes | **3** consecutive |
| `cargo test -p wormhole-ui --features storage --lib settings::` | **pass** (24 filtered `settings::` tests) |

## Accepted findings and fixes

| ID | Sev | Location | Invariant | Evidence | Fix | Verification |
|---|---|---|---|---|---|---|
| SETA-001 | P1 | `storage_store.rs` JSON bridge | Forward-compat keys must survive UI↔storage convert | Storage keeps `unknown_fields`; UI `AppSettings` had none → stage/apply stripped `FutureFeatureFlag` | UI `AppSettings::unknown_fields` flatten + round-trip test | `unknown_fields_survive_stage_apply_reload` |
| SETA-002 | P1 | `view_model.rs` `persist_or_rollback` | Failed immediate setter after `stage` must not clear dirty | `dirty=false` after rollback left memory≠disk with clean flag | Restore `was_dirty` on save failure | `failed_setter_after_stage_preserves_dirty` |
| SETA-003 | P2 | adapter tests / docs | Missing-file, schema stamp, reload-discard, array-root, concurrency | Attack list under-tested on glue | Tests + module concurrency note; compile-time schema const assert | `missing_file_*`, `apply_stamps_*`, `reload_discards_*`, `array_root_*` |
| SETA-004 | P2 | `CURRENT_SCHEMA_VERSION` | UI vs storage stamp must not drift | Duplicated `= 8` constants | `const _: () = assert!(UI == storage)` in adapter | compile-time |
| SETA-005 | P2 | `SettingsViewModel` persist | Disk stamp must match in-memory schema after apply | Adapter stamped storage copy only; VM kept staged `settings_schema_version = 3` | `stamp_and_save` before every persist path | `apply_stamps_current_schema_version` asserts `vm.current()` |
| SETA-006 | P3 | `03-storage.md` / `17-tree-settings-vm.md` | Docs must describe glue contracts | Docs omitted unknown_fields / dirty / stamp / empty-vs-missing | Updated settings behaviour + UI glue notes | doc review |
| SETA-007 | P3 | `SettingsViewModel` rustdoc | Comment claimed rollback to last persisted snapshot | After SETA-002 rollback is pre-setter (+ prior dirty) | Corrected struct docs | review |

## Rejected / residual

| Candidate | Disposition |
|---|---|
| Atomic `settings.json` replace (temp+rename) | **Rejected** — C# `WriteAllBytes` parity; storage-writes ledger same |
| Scrub hostile `Password` keys from `unknown_fields` on save | **Rejected** — storage retains unknown keys; legitimate writes still assert no secret needles |
| Process-wide lock across multiple `StorageSettingsStore` instances on one path | **Rejected / residual** — prefer one `Arc` writer; each instance owns its own mutex (documented) |
| Concurrent apply races on one VM | **Documented** — mutations need `&mut self` (single-threaded per VM); one `Arc` serializes `save` via storage write lock |
| Replace JSON bridge with hand-written field copy | **Rejected** — churn; wire-format parity via serde is the point |
| Fail-open corrupt JSON like `JsonFileSettingsStore` | **Rejected** — intentional storage fail-closed semantics for this adapter |

## Attack coverage

| Attack | Result |
|---|---|
| Corrupt / partial / array / whitespace-only JSON | Fail closed (`SettingsError::Corrupt`) through adapter; VM `new` fails |
| Empty file vs missing file | Empty → Corrupt; missing → defaults, no file created |
| Secrets needles in written JSON | `assert_no_settings_secrets` on stage/apply and unknown-field apply |
| Dirty without apply | `stage` does not create/write file |
| Concurrent apply | Documented single-threaded VM + single-Arc write lock |
| Schema stamp drift | VM + adapter stamp `CURRENT_SCHEMA_VERSION`; const assert UI==storage |

## Simplify notes (post-adversarial)

- `stamp_and_save` shared by `save` / `apply` / `persist_or_rollback`
- `bridge_json` shared by `to_storage` / `from_storage`
- Test helper `assert_no_settings_secrets` aligned needle checks

## Adversarial clean cycles (final implementation)

1. **Pass A** (contract → boundary → state → concurrency → security → integration → tests): no accepted findings after SETA-* fixes + simplify delta (`stamp_and_save` / `bridge_json` / unknown_fields / dirty preserve).
2. **Pass B** (reverse: tests → security → concurrency → state → docs): no accepted findings.

## iterative-review-simplify clean cycles

1. Reuse / efficiency / quality — applied `stamp_and_save` + `bridge_json`; then continued.
2. Secret-needle test helper — applied; reset.
3–5. Three consecutive clean cycles (reuse/efficiency/quality; reverse orders) — no further validated edits.

Post-simplify adversarial re-run: **2** clean passes (required because simplify edited implementation).

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-ui --features storage --lib settings::
```

**Result:** 24 passed. Unrelated `wormhole-tunnels` unused-import warnings may appear when default `session` feature compiles; they are out of scope.
