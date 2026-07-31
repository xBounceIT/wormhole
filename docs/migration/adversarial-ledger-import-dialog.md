# Adversarial ledger — mRemoteNG import dialog Fake VM glue (`wormhole-ui`)

**Scope:**
- `rust/crates/wormhole-ui/src/mremoteng_import_dialog.rs` (+ crate-root re-exports / `import` feature in `lib.rs` / `Cargo.toml`)
- Composes `wormhole-import` (`parse_xml_path`, `plan_nodes`, `FakeImportSkipReporter`, `apply_import_plan`) + `FakeMRemoteNgImportLab` temp SQLite apply
- Docs: `12-import.md` (dialog VM section), `08-ui.md` cross-ref, `feature-matrix.md` (Import row), `README.md` index
- this ledger

**Out of scope:** C# `MRemoteNgImportDialog.xaml` / GPUI chrome; live `FileOpenPicker` COM; CredMgr commit on apply; encrypted-password UX beyond `set_import_password`; tree refresh after import.

**Compared against:** C# `MRemoteNgImportDialogViewModel` pick → plan counts → soft-skip InfoBar → optional commit  
**Authority:** full adversarial-review-fix (edit in scope)  
**Gates:** 2 clean adversarial cycles + 3 clean iterative-review-simplify cycles

## Baseline

- Before review: XML parse/plan + skip report + apply stub in `wormhole-import`; feature-matrix Import row **Spike** (no dialog VM)
- Attack focus: fail-closed empty path / parse / DOCTYPE; no password in VM/preview `Debug`; double-apply must not duplicate SQLite rows; Fake path UI counts-only `Debug`; path/password change clears stale plan; soft-skip summary via reporter

## Findings

| ID | Sev | Location | Issue | Evidence | Disposition |
|---|---|---|---|---|---|
| IDlg-001 | P1 | `apply` | Second apply on same plan could insert duplicate nodes | SQLite row count would double | **Fixed** — `AlreadyApplied` + regression |
| IDlg-002 | P2 | `MRemoteNgImportDialogVm::Debug` | Must not echo `import_password` / planned secrets | Task invariant | **Fixed** — counts-only VM `Debug` + regression |
| IDlg-003 | P2 | `set_xml_path` / `set_import_password` | Stale plan after path/password change | C# re-plan on file/password change | **Fixed** — `clear_plan_state` + regressions |
| IDlg-004 | P2 | `pick_and_plan_from_ui` | Empty / whitespace Fake path must fail closed | Boundary lane | **Fixed** — `validated_path` + regressions |
| IDlg-005 | P2 | `parse_xml_path` / DOCTYPE | Hostile XML must not reach apply | XXE lane | **Fixed** — plan fails; apply `NotPlanned` + regression |
| IDlg-006 | P2 | `FakeMRemoteNgImportPathUi::Debug` | Must not echo forced path/error text | Fake Debug policy | **Fixed** — counts-only `Debug` + regression |
| IDlg-007 | P3 | `From<ImportError>` | Wrong `Result` associated type in first draft | Compile error | **Fixed** — returns `Self` |
| IDlg-008 | P3 | docs | Ledger + README + feature-matrix + `12-import` section | Policy | **Fixed** — this ledger + doc updates |
| IDlg-R1 | — | Debounce on path text | C# may debounce inspect | Host-owned like other VMs | **Rejected** |
| IDlg-R2 | — | GPUI dialog chrome | Explicit lab VM-only scope | **Rejected** |
| IDlg-R3 | — | CredMgr on apply | Apply stub still node-only | **Rejected** — documented non-goal |
| IDlg-R4 | — | Merge into `wormhole-import` | UI VM belongs in `wormhole-ui` | **Rejected** |
| IDlg-R5 | — | Single-read optimize inspect+parse | Double read acceptable for lab | **Rejected** — simplify noted |

## Fixes applied

- `mremoteng_import_dialog.rs` — `MRemoteNgImportDialogVm`, `FakeMRemoteNgImportPathUi`, `FakeMRemoteNgImportLab`, apply sink trait, 15 regressions
- `lib.rs` / `Cargo.toml` — `import` feature (`storage` + `wormhole-import`), re-exports
- `docs/migration/12-import.md` — dialog VM behaviour + verification
- `docs/migration/08-ui.md` — cross-ref
- `docs/migration/feature-matrix.md` — Import row → Lab (dialog VM)
- `docs/migration/README.md` — index row
- `docs/migration/adversarial-ledger-import-dialog.md` — this ledger

## Gate record

### Adversarial loop

| Cycle | Strategy | Accepted findings | Result |
|---|---|---|---|
| Adv-0 | Contract → boundary → security (Debug/no secrets) → state (stale plan / double apply) | IDlg-001…008 | Fixed; reset |
| Adv-1 | Reverse: tests-as-oracles → Fake reporter force → HTTP/Serial skip summary | None (IDlg-R1…R5 rejected) | Clean (1/2) |
| Adv-2 | Forward: pick+plan+apply round-trip, Storage sink parity via Fake lab | None | Clean (2/2) |

### Iterative-review-simplify

| Cycle | Reuse | Efficiency | Quality/Bugs | Accepted | Result |
|---|---|---|---|---|---|
| Sim-1 | Reuse `wormhole-import` plan/skip/apply; temp SQLite Fake lab | Single module behind `import` feature | `AlreadyApplied`; `_dir` keeps TempDir alive | **Fixed** → reset adv |
| Sim-2 | `FakeImportSkipReporter` not duplicated; trait sink thin | No GPUI / COM deps | Unused import trimmed | None | Clean (1/3) |
| Sim-3 | VM `Debug` counts-only; preview safe struct | Ledger + verification commands | None | None | Clean (2/3) |
| Sim-4 | No further extraction | Diff hygiene | None | None | Clean (3/3) |

Post-simplify adversarial re-run (Adv-1/Adv-2 after Sim-1): no new accepted findings.

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-ui --no-default-features --features import --lib mremoteng_import
cargo test -p wormhole-import
```

**Result (final):** `mremoteng_import` **15** passed; `wormhole-import` full crate green; 0 failed.

```powershell
git diff --check -- rust/crates/wormhole-ui/src/mremoteng_import_dialog.rs docs/migration/adversarial-ledger-import-dialog.md docs/migration/12-import.md docs/migration/README.md docs/migration/feature-matrix.md docs/migration/08-ui.md
```

**Diff hygiene:** clean (no whitespace errors on scoped paths).
