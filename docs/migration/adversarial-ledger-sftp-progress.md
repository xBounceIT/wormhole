# Adversarial ledger — SFTP transfer progress callback glue

**Scope:** `rust/crates/wormhole-sftp/src/progress.rs` (`report_progress`, `report_to_callback`, `run_fake_transfer`, `TransferProgress` / callback / errors, Fake chunked transfer), `docs/migration/11-sftp.md` progress section, feature-matrix SFTP upload/download Lab note, README ledger link  
**Authority:** adversarial-review-fix (edit in scope; no C# mutations; no strip UI binding; no live russh progress hooks)  
**Preserved:** Fail-closed negatives / percent mul overflow; cancel-before-snapshot; unknown/`0` total → no percent; clamp when transferred > total; size-only snapshots / errors  
**Baseline (pre-fix):** `cargo test -p wormhole-sftp` green; progress unit pins present but Fake doc claimed a forced final snap to `total`; cancel/`report_to_callback` / 0%–100% / `i64` width pins thin  
**Compared against:** C# `SftpSession` Upload/Download `IProgress<long>` + cancel in callback; `TransferItemViewModel.ProgressFraction` (`ExpectedBytes <= 0` → 0, else `Clamp`)

---

## Accepted findings and fixes

| ID | Sev | Location | Invariant / evidence | Fix | Verification |
|---|---|---|---|---|---|
| PROG-01 | P2 | `run_fake_transfer` rustdoc | Claimed “final report at `total` when `total > 0`” but loop only advances to `fake_payload_len` | Rewrite rustdoc; pin no forced snap | `fake_transfer_payload_below_total_does_not_force_final_snap` |
| PROG-02 | P2 | `progress::tests` | Cancel precedence, 0%/100%, `report_to_callback` cancel/invalid sink skip, Fake `total > i64::MAX`, empty pre-cancel not machine-checked | Add focused regression tests | those tests |
| PROG-03 | P3 | `11-sftp.md` / feature-matrix / README | Progress Fake contract + ledger link / Lab note missing | Doc bullets + matrix Lab note + ledger + README row | docs review |

### Simplify delta (post-adversarial)

| ID | Sev | Location | Change | Verification |
|---|---|---|---|---|
| S-01 | — | `report_progress` percent | Drop redundant `checked_div` / `try_from`/`unwrap_or`; `checked_mul` then `/ t` (`t > 0`) and `min(100) as u8` | full `wormhole-sftp` suite; adversarial re-looped to 2 clean |

---

## Rejected candidates

| Candidate | Reason |
|---|---|
| Widen percent math to `u128` (accept `i64::MAX`×100) | Conflicts with documented fail-closed mul overflow; sizes that overflow `u64`×100 are not realistic SFTP payloads |
| Wire mid-transfer progress into `TransferQueue` / `FakeSftpBackend` | Documented host / follow-up; this stub is Fake chunk driver + normalize API |
| Mirror C# Completed → fraction `1.0` inside `TransferProgress` | Completed snap is strip/host state; stub emits sizes only |
| Soften cancel to still deliver last snapshot | Fail-closed cancel-before-report matches C# `ThrowIfCancellationRequested` before `Report` |
| Replace hand `Display`/`Debug` with `thiserror` | Two static variants; explicit Debug keeps credential-free surface obvious |
| Relax `Ordering::SeqCst` on cancel flag | Negligible cost; cancel correctness prefers strongest order |
| Map `Some(0)` early in `run_fake_transfer` signed total | `report_progress` already maps `0` → unknown; change is taste-only |
| Drop defensive `Some(t) if t > 0` after `Some(0)`→`None` | Guard documents the percent invariant; left as-is after S-01 |

---

## Adversarial clean passes (2 required)

Reset after each fix batch and after simplify deltas that touched implementation (S-01).

### Clean pass 1 — order: concurrency → security → state → contract → tests

- Cancel flag is `SeqCst`; callback is `&mut` (single-threaded report path); mid-chunk cancel stops further reports.
- Snapshots / errors / Debug carry sizes only — no paths or credential-shaped text (pinned).
- Normalize is pure; Fake local counter does not report after Cancelled/Invalid.
- Cumulative bytes → optional percent; unknown/`0` omit percent; overflow fail closed; clamp > total.
- **Accepted findings:** none.

### Clean pass 2 — order: integration → boundaries → test resistance → operability → contract

- `lib.rs` re-exports; `11-sftp.md` + feature-matrix Lab note match Fake/`report_progress` contracts.
- Negatives, cancel-first, 0%/100%, mul overflow, `total > i64::MAX`, zero chunk, empty pre-cancel, no forced final snap.
- `report_to_callback` does not invoke the sink on Cancelled/Invalid.
- No secret-shaped logging on this surface.
- **Accepted findings:** none.

`adversarial_clean_passes = 2` (re-established after S-01).

---

## Iterative-review-simplify (3 clean cycles)

Each cycle: Code Reuse → Code Efficiency → Code Quality and Bugs (+ simplify discipline).

| Cycle | Themes | Outcome |
|---|---|---|
| 1 (fix) | Quality (redundant `checked_div` + dead `try_from`/`unwrap_or` after `min(100)`) | S-01 applied → adversarial re-looped to 2 clean; simplify counter reset |
| 1 (clean) | Reuse (keep progress API separate from queue); efficiency (reject SeqCst downgrade); quality (retain `t > 0` percent arm) | Clean |
| 2 | Reject `u128` widen / queue wiring / Completed snap / thiserror | Clean |
| 3 | Docs/matrix parity; Fake `fake_payload_len` contract; no further validated churn | Clean |

`simplify_clean_passes = 3`.

---

## Regression tests added/updated

- `cancel_takes_precedence_over_invalid_counts`
- `exact_zero_and_hundred_percent`
- `report_to_callback_respects_cancel_flag`
- `report_to_callback_skips_sink_on_invalid`
- `fake_transfer_payload_below_total_does_not_force_final_snap`
- `fake_transfer_total_above_i64_max_fail_closed`
- `fake_empty_payload_respects_pre_cancel`
- Existing: known/unknown/zero total, clamp, negatives, cancel, mul overflow, Fake chunks/unknown/cancel/zero-chunk/empty, error Display

---

## Final verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-sftp
```

Results: lib 46 passed (19 `progress::`); `serialize_queue` 12 passed; doc-tests 0.
