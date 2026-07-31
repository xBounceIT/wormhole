# Adversarial ledger — logging boot / settings → redaction glue

**Scope:** `rust/crates/wormhole-app/src/logging_boot.rs`, binary bootstrap order in `src/bin/wormhole_app.rs`, docs `13-update-logging.md`  
**Authority:** full adversarial-review-fix (edit in scope; no tunnels / surface-win churn)  
**Impl:** `a9e3a084-42c8-49f9-9de3-5aa2cbf153fb`  
**Attack focus:** `apply_logging_boot` → existing `redact_log_text` (no reimplementation); `FakeLogSink`; retention `1..=365` (C# `LogFiles.NormalizeRetentionDays`); `production_default` before `init_tracing`  
**Baseline:** `cargo test -p wormhole-app` green before review  
**Final:** `cargo test -p wormhole-app` — **42** lib + **3** smoke green  

Compared against C#: `Helpers/LogFiles.cs`, `Wormhole.Tests/Helpers/LogFilesTests.cs`, `Models/AppSettings.LogRetentionDays`, Serilog boot in `App.xaml.cs`.

---

## Gate summary

| Gate | Result |
|---|---|
| Adversarial clean passes | **2** consecutive (post-fix + post-simplify re-run) |
| Iterative-review-simplify clean passes | **3** consecutive |
| `cargo test -p wormhole-app` | **pass** (42 lib + 3 smoke) |
| `git diff --check` (scoped) | **pass** |

---

## Accepted findings

### LOGB-01 — Retention boundary under-tested vs C# theory (`P2`) — **fixed**

- **Where:** `normalize_retention_days` / `apply_logging_boot` tests
- **Invariant:** C# `LogFilesTests` pins `1`, `14`, `365`, `0→14`, `366→14`, `-1→14`
- **Evidence:** Pre-review tests covered `0`, `30`, `365`, `999` only — missed MIN edge and `366`/`-1`
- **Fix:** `normalize_retention_days_matches_csharp_theory` + `csharp_retention_constants_match`; also pins `i32::MIN` / `i32::MAX` → default
- **Regression:** those two tests

### LOGB-02 — `AppliedLogging` public fields bypassed normalization (`P2`) — **fixed**

- **Where:** `AppliedLogging` struct
- **Invariant:** Type is the *normalized* result of `apply_logging_boot`; retention must not be forgeable as `0` / `999`
- **Evidence:** Public fields + `with_applied` allowed `AppliedLogging { retention_days: 999, … }`
- **Fix:** Private fields + `redaction_enabled()` / `retention_days()` accessors; construct only via `apply_logging_boot` / `Default`
- **Regression:** enrich / Fake tests build via `apply_logging_boot`; binary uses accessors

### LOGB-03 — Docs / comments overstated “enable enricher” for production writer (`P3`) — **fixed**

- **Where:** module rustdoc, `apply_logging_boot` docs, `13-update-logging.md`, binary comment
- **Invariant:** Production file/stderr always redact via `init_tracing` writer hook; `redaction_enabled` gates `enrich_log_line` / `FakeLogSink` only
- **Fix:** Clarified docs + boot table; binary comment matches contract

---

## Rejected candidates

| ID | Severity | Reason |
|---|---|---|
| REJ-01 | — | Wire `AppliedLogging` into `init_tracing` to honor `redaction_enabled=false` — production must always redact; flag is Fake/custom-sink only |
| REJ-02 | — | `FakeLogSink::apply_config` should clear lines — documented; callers use `clear()`; clearing would surprise Lab asserts that keep history |
| REJ-03 | — | Unify `wormhole-ui::normalize_retention_days` with app constants — wrong dep direction (`ui` ↛ `app`); pre-existing UI helper; out of scope |
| REJ-04 | — | Make `FakeLogSink` `Sync` / shared — Lab Fake is single-threaded by design |
| REJ-05 | — | Implement aged-log deletion from `retention_days` — explicit non-goal (host-owned; documented) |
| REJ-06 | — | Remove `production_default` / `FakeLogSink::new` aliases of `Default` — intentional named API for hosts/tests |

---

## Simplify passes (iterative-review-simplify)

| Cycle | Reuse | Efficiency | Quality | Disposition |
|---|---|---|---|---|
| 1 | Locality: move `Default for AppliedLogging` next to type; clarify module/binary docs | — | Doc/contract alignment | **Fixed** |
| 2 | Reject UI normalize merge; reject removing aliases | No findings | No findings | **clean 1** |
| 3 | Reverse: quality → efficiency → reuse | No findings | No findings | **clean 2** |
| 4 | Efficiency-first; reject dropping overlapping apply/theory tests | No findings | No findings | **clean 3** |

---

## Adversarial cycles

| Phase | Cycle | Notes | Disposition |
|---|---|---|---|
| Initial | 1 | All 8 lanes; accepted LOGB-01..03 | **fixes** |
| Post-fix | 1 | Contract → tests | **clean 1** |
| Post-fix | 2 | Reverse: tests → security → docs | **clean 2** |
| Post-simplify re-run | 1 | Focus delta (Default locality + docs) | **clean 1** |
| Post-simplify re-run | 2 | Reverse order | **clean 2** |

---

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-app
```

**Result:** 42 lib + 3 smoke passed. Unrelated sibling-crate churn during review (brief `wormhole-ui` / `wormhole-vnc` mid-edit compile failures) was out of scope and resolved without tunnels/surface-win edits.
