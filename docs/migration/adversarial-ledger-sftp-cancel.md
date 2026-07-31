# Adversarial ledger — SFTP single-flight cancel

**Scope:** `rust/crates/wormhole-sftp/` worker-owned gate + transfer cancel only (`session.rs`, `queue.rs`, `fake.rs` cancel/in-flight paths), `docs/migration/11-sftp.md` cancel notes, README ledger link  
**Authority:** adversarial-review-fix (edit in scope; no C# mutations; no live russh connect)  
**Preserved:** Serialization `peak_in_flight == 1`, mid-op finish-current-op parity with C# `SftpSession.RunAsync`, `public_message` redaction, unsafe-name rejection  
**Baseline (pre-fix):** `cargo test -p wormhole-sftp` green (5 lib + 11 serialize_queue); thin cancel note only

---

## Accepted findings and fixes

| ID | Sev | Location | Invariant / evidence | Fix | Verification |
|---|---|---|---|---|---|
| C-01 | P2 | `serialize_queue.rs` | Queue cancel while waiting on gate not pinned — risk of wrongly Cancelling the holder or skipping the next Completes | `cancel_queued_transfer_skips_then_next_completes`: holder Completed, waiter Cancelled, next Completed; `ops_completed==2`; no remote file for waiter | that test |
| C-02 | P2 | `queue.rs` `cancel_if_running` | Drop vs `set_status(Completed/Failed)` race not unit-pinned — late cancel could clobber terminal strip rows | Doc + unit test that terminal statuses survive `cancel_if_running` | `queue::tests::cancel_if_running_does_not_clobber_terminal_status` |
| C-03 | P3 | `11-sftp.md` / README | Cancel table omitted queue pre-gate row; README missing ledger link | Document four abort timings; link `adversarial-ledger-sftp-cancel.md` | docs review |

Historical production fixes (prior stream, still load-bearing) live in `adversarial-ledger-sftp-vpn.md`: F-01 worker-owned gate, F-02 `InFlightGuard`, F-03 `JobStatusGuard`.

### Simplify delta (post-adversarial)

| ID | Sev | Location | Change | Verification |
|---|---|---|---|---|
| S-01 | — | `queue.rs` `JobStatusGuard` | Removed redundant `finished` flag; Drop always calls `cancel_if_running` (no-op on terminal) | full `wormhole-sftp` suite |

---

## Rejected candidates

| Candidate | Reason |
|---|---|
| Rework gate to Semaphore / AbortHandle kill of backend | Would break “finish current op” parity with C#; mutex+worker already correct |
| Fail / roll back mid-op bytes after caller cancel | Documented: worker finishes; UI row is Cancelled |
| Restore `finished` bool to skip Drop lock on success | Extra mutex lock per completed job is negligible; simpler Drop is preferred |
| Extract shared cancel-test helper across session/queue cases | Two surfaces; duplication is clearer than a helper |
| Zeroize upload buffers after send | Caller-owned bytes; not logged; out of cancel scope |
| Live russh cancel soak | Feature compile-only; deferred with channel wiring |

---

## Adversarial clean passes (2 required)

Reset after each fix batch and after simplify deltas that touched implementation.

### Clean pass 1 — order: concurrency → security → state → contract → tests

- Mid-op / pre-gate / queue waiter cancel: single `_guard` Drop releases tokio `Mutex` once; no poison (tokio gate); `jobs` std `Mutex` recovers via `into_inner`; peak_in_flight stays 1; `in_flight` returns to 0.
- Cancel paths do not log or store credential-shaped text.
- `cancel_if_running` preserves Completed/Failed; close rejects new ops after in-flight.
- Contract: next op / next enqueue Completes after cancel; skipped waiter excluded from `ops_completed`.
- **Accepted findings:** none.

### Clean pass 2 — order: integration → boundaries → test resistance → operability → double-release

- Docs table + README link match four abort timings; `JobStatusGuard` Drop semantics match comments.
- Boundaries: abort before poll (no job), NotFound → Failed then cancel no-op, empty upload payload.
- Test resistance: queue waiter cancel cannot clobber holder; terminal clobber unit-pinned; cancel→next Completes on session and queue.
- Double-release: early return on closed/skip and normal completion all rely on one RAII gate guard; no `mem::forget`.
- **Accepted findings:** none.

`adversarial_clean_passes = 2` (re-established after S-01).

---

## Iterative-review-simplify (3 clean cycles)

Each cycle: Code Reuse → Code Efficiency → Code Quality and Bugs (+ simplify discipline).

| Cycle | Themes | Outcome |
|---|---|---|
| 1 | Reuse (session vs queue cancel tests kept distinct); efficiency (reject restoring `finished`); quality (Drop/`cancel_if_running` single policy) | S-01 applied → adversarial re-looped to 2 clean |
| 2 | Upload `'static` clone required for worker; fake `InFlightGuard` before await untouched; no further DRY | Clean |
| 3 | Gate acquire/skip/close paths; poison recovery; docs parity with `11-sftp.md` | Clean |

`simplify_clean_passes = 3`.

---

## Regression tests added/updated

- `tests/serialize_queue.rs` — `cancel_queued_transfer_skips_then_next_completes` (holder Completes, waiter Cancelled, next Completes)
- `src/queue.rs` — `cancel_if_running_does_not_clobber_terminal_status`
- Existing pins retained: `cancel_mid_op_does_not_overlap_backend`, `cancel_while_queued_skips_backend_then_next_succeeds`, `cancel_transfer_marks_job_cancelled`

---

## Final verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-sftp
```

Results: lib 6 passed; serialize_queue 12 passed; doc-tests 0.
