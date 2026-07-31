# Adversarial ledger — diagnostics + soak stubs

**Scope:** `rust/crates/wormhole-diagnostics/`, `rust/crates/surface-lab/` `--diagnostics` wiring only, `docs/migration/19-diagnostics-soak.md`  
**Authority:** full adversarial-review-fix (edit in scope; no C#; no tunnel locate rewrite)  
**Baseline:** `cargo test -p wormhole-diagnostics` — 6 passed / 1 ignored before review  
**Final:** **14** passed / 1 ignored; `cargo run -p surface-lab -- --diagnostics` prints secrets-free report  

---

## Gate summary

| Gate | Result |
|---|---|
| Adversarial clean passes | **2** consecutive (post-fix + post-simplify re-run) |
| Iterative-review-simplify clean passes | **3** consecutive |
| `cargo test -p wormhole-diagnostics` | **pass** (14 + 1 ignored) |
| `cargo run -p surface-lab -- --diagnostics` | **pass** |
| `git diff --check` (scoped) | **pass** |

---

## Accepted findings

### DIAG-01 — Sidecar search could traverse Wormhole secrets dirs (`P1`) — **fixed**

- **Where:** `sidecars.rs` `probe_one` / `candidate_paths` consumers
- **Invariant:** Attack focus — locate must not walk `%LOCALAPPDATA%\Wormhole\{keys,tunnels}`
- **Evidence:** `WORMHOLE_SIDECAR_DIR` (or forged candidates) under those dirs would `is_file()` and `format_report` would print the Present path
- **Fix:** `touches_wormhole_secrets_dir` + `filter_secret_dir_candidates`; Present under secrets → Missing
- **Regression:** `filter_drops_secret_dir_candidates`, `matrix_never_searches_or_reports_secrets_dirs`, `touches_wormhole_secrets_dir_detects_keys_and_tunnels`

### DIAG-02 — Format path could leak credential-blob directories (`P1`) — **fixed**

- **Where:** `report.rs` `format_report` / `format_sidecar_row`
- **Invariant:** Report must never emit `Wormhole\keys` / `Wormhole\tunnels`
- **Fix:** Format-time filter for forged Present paths; Missing counts ignore secret candidates; logs_dir under secrets → `(redacted)`
- **Regression:** `format_redacts_forged_secrets_sidecar_path`, `format_redacts_forged_secrets_logs_dir`, `format_missing_counts_ignore_secret_candidates`

### DIAG-03 — Registry probe soft-failure / `ProbeFailed` dead (`P2`) — **fixed**

- **Where:** `webview2.rs` `probe_webview2_runtime` / `read_pv`
- **Invariant:** Attack focus — registry probe failures soft; no panic
- **Evidence:** `read_pv` never returned `Err`; `ProbeFailed` unreachable; missing vs unexpected open not distinguished
- **Fix:** Missing key statuses → `Ok(None)`; unexpected `RegOpenKeyExW` → `Err`; aggregate to `ProbeFailed` only when every hive errs with no miss; `catch_unwind` test
- **Regression:** `probe_never_panics`, `missing_key_statuses_are_recognized`

### DIAG-04 — Assignment redaction claimed but not enforced on format (`P2`) — **fixed**

- **Where:** `report.rs` `format_report`
- **Invariant:** No unredacted `password=` / `token=` / `secret=` in report text
- **Evidence:** Forged `app_version: "password=s3cret"` would print raw; doc claimed hard rule
- **Fix:** `redact_secret_assignments` post-pass on formatted text
- **Regression:** `format_scrubs_forged_assignment_secrets`; tightened `assert_no_secret_leaks`

### DOC-01 — Docs could be read as soak/hardware gate pass (`P2`) — **fixed**

- **Where:** `docs/migration/19-diagnostics-soak.md`
- **Invariant:** Attack focus — docs must not claim soak/hardware gates passed
- **Fix:** Status + explicit **Gate status** section; non-goal; ledger link; secrets-dir / soft-probe notes; “unredacted” assignment wording

---

## Rejected candidates

| ID | Severity | Reason |
|---|---|---|
| REJ-01 | — | Rewrite `wormhole-tunnels::candidate_paths` to exclude secrets dirs — out of diagnostics edit scope; filter at diagnostics boundary is sufficient |
| REJ-02 | — | Depend on `wormhole-app` / `wormhole-secrets-win` for shared redaction — would pull heavy deps into a support-report crate |
| REJ-03 | — | Hide `logs_dir` username — docs require path-only mirror of app logs dir; not a credential blob |
| REJ-04 | — | Symlink/junction from staging dir into `keys/` — speculative; path string still non-secrets |
| REJ-05 | — | Extract surface-lab flag parser for unit tests — wiring is three lines; binary-only smoke covered by `cargo run` |
| REJ-06 | — | Live 8h soak / hardware RSS gates — explicit non-goals / placeholders |

---

## Simplify passes (iterative-review-simplify)

| Cycle | Reuse | Efficiency | Quality | Disposition |
|---|---|---|---|---|
| 1 | Drop tunnels-only smoke test; tidy `Path` import; collapse RegOpen if | — | Doc assignment wording | **Fixed** |
| 2 | No findings | No findings | No findings | **clean 1** |
| 3 | No findings | No findings | No findings | **clean 2** |
| 4 | No findings | No findings | No findings | **clean 3** |

---

## Adversarial cycles

| Pass | Strategy | Result |
|---|---|---|
| Adv-1 | Contract → boundaries → security → integration → tests | DIAG-01..04, DOC-01 accepted → fixed; counter reset |
| Adv-2 | Security → integration → contract (independent order) | DIAG-04 assignment scrub gap found → fixed; counter reset |
| Adv-3 (post-simplify) | Security + boundary re-read of delta | **clean 1** |
| Adv-4 (post-simplify) | Operability + test-resistance re-read | **clean 2** |

---

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-diagnostics
cargo run -p surface-lab -- --diagnostics
```

- `cargo test -p wormhole-diagnostics` → **14 passed, 1 ignored**
- `cargo run -p surface-lab -- --diagnostics` → secrets-free report; early exit (no gate smokes)
- Context7 MCP unavailable; no new crates.io deps

---

## Closure

- No accepted non-blocked findings remain
- **2** consecutive adversarial clean cycles after last fix batch
- **3** consecutive iterative-review-simplify clean cycles
- Unrelated user changes outside scope left intact
