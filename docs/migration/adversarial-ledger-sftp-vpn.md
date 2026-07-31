# Adversarial ledger — SFTP + OpenVPN/Fortinet sidecar wiring

**Scope:** `rust/crates/wormhole-sftp/`, `rust/crates/wormhole-tunnels/` OpenVPN/Fortinet/shared spawn path (+ CRLF/`ovpn_backed` compile unblock in providers), `rust/crates/wormhole-app/` sftp feature wiring only, `docs/migration/11-sftp.md` (+ `07-tunnels-mcp.md` note)  
**Authority:** adversarial-review-fix (edit in scope; no Go sidecars; no C# mutations)  
**Preserved:** WireGuard READY/SOCKS bounds, locate `..`/NUL rejection, lease `EstablishRefGuard` coalesce  
**Baseline (pre-fix):** `cargo test -p wormhole-sftp -p wormhole-tunnels -p wormhole-app` green; cancel probe showed `peak_in_flight=2`

---

## Accepted findings and fixes

| ID | Sev | Location | Invariant / evidence | Fix | Verification |
|---|---|---|---|---|---|
| F-01 | P0 | `session.rs` gate | Abort mid-op dropped `MutexGuard` while backend still in flight → `peak_in_flight=2` | Worker task owns mutex until backend future completes; caller awaits oneshot | `cancel_mid_op_does_not_overlap_backend` |
| F-02 | P1 | `fake.rs` `enter`/`leave` | Cancel mid-delay skipped `leave()` → leaked `in_flight` | `InFlightGuard` RAII created before any `.await` | cancel + concurrent tests |
| F-03 | P1 | `queue.rs` status | Abort of `enqueue_and_run_file` left job `Running` forever | `JobStatusGuard` → `Cancelled` unless terminal status recorded | `cancel_transfer_marks_job_cancelled` |
| F-04 | P1 | `error.rs` / queue | `Backend`/`Operation` Display/Debug and job.error could echo credential-shaped text | `public_message`; redacted Display/Debug; queue stores `public_message` only | unit + `transfer_failure_error_hides_backend_secrets` |
| F-05 | P2 | `fake.rs` `rename` | Destination leaf not checked with `is_safe_remote_name` | `reject_unsafe_leaf` on rename target | `rename_rejects_unsafe_destination_name` |
| F-06 | P1 | OpenVPN/Fortinet parity | Hang/secret-not-in-error + manager missing/coalesce only fully pinned for WG | Hang tests for OVPN/Forti; Fortinet manager BinaryNotFound; OpenVPN coalesce | `sidecar_control_plane.rs` |
| F-07 | P2 | `providers/mod.rs` (concurrent) | Bare CR / double-spaced file + `expect_err` needing `Debug` on `dyn TunnelInstance` broke `wormhole-tunnels` build | Rewrite LF `mod.rs`; match-style asserts in `ovpn_backed` tests | `cargo test -p wormhole-tunnels` |

---

## Rejected candidates

| Candidate | Reason |
|---|---|
| Zeroize upload buffers after send | Caller-owned bytes; not logged; live russh path deferred |
| Fail enqueue when worker skipped after pre-gate cancel | Correct: no backend start; job → Cancelled via guard |
| Abstract OpenVPN/Fortinet/WG providers further | Shared `establish_sidecar_instance` already; struct duplication matches prior WG review |
| Soften `redact_secretish` `"secret"` marker | Intentional conservative UI/log redaction |
| Rewrite Go sidecars / mutate C# | Explicitly out of scope |
| Fix `wormhole-import` beyond workspace `quick-xml` pin | Unrelated crate; only removed invalid `std` feature so workspace resolves |

---

## Adversarial clean passes (2 required)

Reset after each fix batch and after simplify deltas that touched implementation.

### Clean pass 1 — order: concurrency → security → state → contract → tests

- Cancel mid-op / transfer abort: peak=1; job Cancelled; close rejects new ops.
- Secrets absent from Display/Debug/`public_message`/job.error; hang errors omit stdin markers.
- OpenVPN/Fortinet BinaryNotFound ≠ Up; shared READY bounds unchanged for WG.
- **Accepted findings:** none.

### Clean pass 2 — order: integration → boundaries → test resistance → operability → security

- App `sftp` feature wires `SftpHandle`; `--features russh` links `russh-sftp =2.3.0`.
- Boundaries: unsafe rename, empty tunnel secret, missing binary, hang timeout.
- Test resistance: cancel probe that previously failed now asserts peak=1; FIFO acquire order pinned.
- **Accepted findings:** none.

`adversarial_clean_passes = 2`.

---

## Iterative-review-simplify (3 clean cycles)

Each cycle: Code Reuse → Code Efficiency → Code Quality and Bugs (+ simplify discipline).

| Cycle | Themes | Outcome |
|---|---|---|
| 1 | Reuse (`reject_unsafe_leaf`); efficiency (upload/download `.map`); quality (`JobStatusGuard.finished` bool vs id sentinel); docs table fix | Applied → adversarial re-looped to 2 clean |
| 2 | Provider duplication intentional; upload byte clone required for `'static` worker; Drop+kill_on_drop for sidecars untouched | Clean |
| 3 | No further validated churn; ledger/docs aligned; WG suite green | Clean |

`simplify_clean_passes = 3`.

---

## Regression tests added/updated

- `wormhole-sftp/tests/serialize_queue.rs` — cancel mid-op, transfer Cancelled, FIFO fairness, rename unsafe, close-after-inflight, secret-hide
- `wormhole-sftp/src/error.rs` — Display/Debug/public_message redaction units
- `wormhole-tunnels/tests/sidecar_control_plane.rs` — OpenVPN/Fortinet hang+secret, Fortinet manager missing, OpenVPN coalesce

---

## Final verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-sftp -p wormhole-tunnels -p wormhole-app
cargo test -p wormhole-sftp --features russh
```

Results: all green (sftp lib+serialize_queue; tunnels lib+lease+sidecar; app smoke; russh feature link).
