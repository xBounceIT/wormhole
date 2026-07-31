# Adversarial ledger — TunnelManager lease glue

**Scope:** `rust/crates/wormhole-tunnels/src/manager.rs`, `src/lease.rs`, `tests/lease_coalesce.rs`; docs [`07-tunnels-mcp.md`](07-tunnels-mcp.md) / README index.  
**Authority:** full adversarial-review-fix (edit in scope; no child agents; **no** live VPN).  
**Baseline:** `cargo test -p wormhole-tunnels --test lease_coalesce` green (17 tests) before this pass.  
**Out of scope:** Provider/sidecar binaries; SOCKS liveness probe (C# `IsLoopbackEndpointAliveAsync`); provider-level `CancellationToken` abort mid-OTP; MCP host; establish-path glue per kind.

## Gate status

| Gate | Result |
|---|---|
| Adversarial clean passes | **2** consecutive (independent attack order; post-simplify re-run also clean) |
| iterative-review-simplify clean passes | **3** consecutive |
| `cargo test -p wormhole-tunnels` | **pass** (lease_coalesce **21** + crate suite) |

## Accepted findings and fixes

| ID | Sev | Location | Invariant | Evidence | Fix | Verification |
|---|---|---|---|---|---|---|
| TL-01 | P0 | `manager.rs` `release_entry` | Last release must not race a concurrent `establish` into a zero-ref entry still mapped in the pool (closing-instance hand-out). C# holds one `_poolGate` for `RefCount--` + `EvictLocked`. | Pre-fix: entry lock dropped before pool eviction → joiner could `ref_count += 1` on `instance=None` and await the Shared `Ok(old)` while release closed it. | Hold **pool then entry** across zero-ref + eviction (same order as `acquire_entry`). | `last_release_racing_establish_never_hands_out_closed_instance` |
| TL-02 | P1 | `manager.rs` `acquire_entry` | Zero-ref / cancelled entries must never be reused (defense in depth). | Same race window; C# never observes zero-ref while mapped. | `entry_unusable_for_reuse` refuses `ref_count == 0` / `cancelled` / stale / dead. | Same race test + UpdatedAt / Failed / Closed suite |
| TL-03 | P3 | `lease.rs` | Docs / Debug must not imply async release or dump internals. | Rustdoc said “awaiting `release`” (sync); no `Debug` made `expect_err` awkward; secret markers must stay out of `{:?}`. | Fix rustdoc; opaque `Debug` (`armed` only). | `lease_debug_is_opaque` |

## Attack lanes (covered / residual)

| Attack | Disposition |
|---|---|
| Double establish race (last release × new establish) | **Fixed** (TL-01/02) + stress regression |
| Dispose order / last lease closes | **Covered** — `last_lease_closes_underlying_instance`, `last_lease_release_evicts_pool_entry` |
| UpdatedAt bump with outstanding lease | **Covered** — `updated_at_bump_invalidates_pooled_tunnel` |
| UpdatedAt bump mid-establish | **Covered** — `updated_at_bump_during_in_flight_establish_starts_fresh` |
| Cancel mid-establish (sole waiter) | **Covered** — `drop_mid_establish_releases_refcount_and_cancels` |
| Partial cancel (one of two coalesce waiters) | **Covered** — `one_of_two_waiters_cancel_other_still_gets_lease` |
| Failed / Closed fail-closed fresh establish | **Covered** |
| Concurrent coalesce → one OTP | **Covered** — `coalesce_concurrent_establish_calls_one_provider` |
| Secret / fail_next in Debug | **Covered** — manager / Fake / lease Debug + `manager_errors_never_echo_secret_blob` |
| Typed shared errors (`BinaryNotFound` / `NotImplemented` / …) | **Covered** — `EstablishSharedError` ↔ `TunnelError`; missing-binary via manager |

## Rejected / residual

| Candidate | Disposition |
|---|---|
| SOCKS liveness probe on reuse | Rejected / deferred — no real sidecar listener in Fake path; prior tunnels-mcp ledger same |
| Provider `CancellationToken` mid-OTP abort | Rejected / deferred — trait has no cancel; orphan-close after provider returns matches skeleton |
| Sync Drop without tokio skips `close` | Rejected — documented warn; leases normally release on runtime (prior ledger) |
| Fold pool+entry into one mutex like C# | Rejected — current dual-lock + ordered acquire is sufficient after TL-01; larger churn |
| Call `evict_if_same` from `release_entry` while holding pool | Rejected — would re-lock pool (deadlock); inline eviction kept |
| Reduce race-test rounds (80 → N) | Rejected — suite finishes ~0.26s; stress is the point |

## Adversarial clean cycles (final implementation)

1. **Pass A** (concurrency → security → state → contract → tests): lock order resurrection, cancel/orphan, UpdatedAt drain, secret Debug, typed errors — no new accepted findings after TL-01..03.
2. **Pass B** (integration → boundaries → test resistance → operability → security): C# `TunnelManager` / `BorrowedTunnelInstance` parity, empty secret vec via Fake, duplicate providers, close log `config_id` only — no new accepted findings.

Post-simplify re-run on `entry_unusable_for_reuse` + close-log delta: both orders clean again.

`adversarial_clean_passes = 2`.

## iterative-review-simplify clean cycles

Each cycle: Code Reuse → Code Efficiency → Code Quality and Bugs (+ simplify discipline).

| Cycle | Themes | Outcome |
|---|---|---|
| 1 | Reuse (`entry_unusable_for_reuse`); quality (close log includes `config_id`, clearer tuple unpack) | Applied; counter reset |
| 2 | Reuse of `evict_if_same` vs inline (keep — avoids pool re-lock); efficiency (race stress OK); quality (no further bugs) | Clean |
| 3 | Docs parity (`07-tunnels-mcp` cancellation / test list); lease Debug opacity already pinned | Clean |

`simplify_clean_passes = 3`.

## Regression tests added/updated

`wormhole-tunnels/tests/lease_coalesce.rs` — **21** tests, including:

- `last_release_racing_establish_never_hands_out_closed_instance`
- `one_of_two_waiters_cancel_other_still_gets_lease`
- `updated_at_bump_during_in_flight_establish_starts_fresh`
- `lease_debug_is_opaque`

## Final verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-tunnels
```

**Result:** green — lib **340** passed; `lease_coalesce` **21** passed; `sidecar_control_plane` **24** passed; 0 failed. No live VPN.
