# Adversarial ledger — Crash WER/dumps glue

**Scope:** `rust/crates/wormhole-diagnostics/src/wer.rs` (new: `WerSettings`/`WerRegistry`+`Fake`+`Real` shim/`CrashSentinel`+`Fake`/`CrashDiagnosticsGlue`/`build_wer_report_section`) + registration/re-exports in `src/lib.rs`.

**Out of scope:** live HKLM writes (real shim is compile-time-only presence); dump collection; `report.rs` closed contract.

**Compared against:** C# `Services/CrashDiagnosticsService.cs` + `Services/Rdp/RdpCrashSentinelService.cs` — WER `LocalDumps` registry (DumpType Full/Mini ↔ DWORD 1/2, `%LOCALAPPDATA%\Wormhole\crashdumps`, MaxFolderSize 10 MB, DumpCount 10).

**Authority:** full adversarial-review-fix (reviewer subagent; parent re-verified)  
**Baseline:** wormhole-diagnostics **26** tests + 1 ignored  
**Final:** wormhole-diagnostics **42** passed + 1 ignored (pre-existing soak placeholder)

**Attack focus:** secret-dir path redaction across separators/offsets (forged `app_exe`/sentinel detail), DWORD vs REG_SZ enforcement, partial-subtree + wrong-type + unknown-DumpType fail-closed, apply-error fail-closed, collect never panics, sentinel record/clear + fail propagation, real hive never touched.

---

## Gate summary

| Gate | Result |
|---|---|
| Adversarial clean passes | **2** consecutive (+ post-IRS delta) |
| Iterative-review-simplify clean passes | **3** consecutive |
| `cargo test -p wormhole-diagnostics` | **pass** (42 + 1 ignored) |
| `cargo check` / `cargo clippy --all-targets` | **pass** / clean in `wer.rs` |
| `git diff --check` (scoped) | **pass** |

---

## Accepted findings and fixes

| ID | Sev | Finding | Fix |
|---|---|---|---|
| P2 | `redact_secret_dir_paths` matched only backslash fragments (forward-slash / leading-position leaks; first-match-in-list order) | Separator-agnostic 4-fragment scan, min-position selection, identifier-fused skip, over-redact |
| P3 | Swapped doc comments on `WER_DEFAULT_DUMP_COUNT` / `WER_DEFAULT_MAX_FOLDER_SIZE_MB` | Corrected |
| P3 | Clippy `unnecessary_map_or` | `is_none_or` |
| P3 | Clippy default-constructed unit struct (test) | Direct construction |
| IRS | Tautological `match` in `RealWerRegistry::query_value` | `&'static str` param + exact name in error |
| IRS | `collect_on_read_failure` didn't pin empty rows | Assertion added |
| IRS | `dump_folder` doc "resolved" vs raw REG_EXPAND_SZ | Doc precision fix |

### Regression tests (2 + strengthened)

`format_redacts_secret_dirs_across_separators_and_offsets` (incl. mid-word skip preserved); `collect_on_read_failure_reports_error_never_panics` (rows empty pinned).

### Rejected candidates

Real-shim non-transactional write (never-run; partial subtree fails closed); REG_EXPAND_SZ unexpanded on read (fake/real contract parity, pinned); redaction duplication vs `report.rs` (out-of-scope); `UnsupportedPlatform` untested (cfg-gated, never-run).

---

## Test command

```powershell
cd rust
cargo test -p wormhole-diagnostics
cargo clippy -p wormhole-diagnostics --all-targets
```

**Counts:** `wer::tests` **15**; full wormhole-diagnostics **42 passed / 1 ignored**.