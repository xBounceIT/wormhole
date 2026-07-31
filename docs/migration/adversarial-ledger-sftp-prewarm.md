# Adversarial ledger — SFTP client prewarm / borrow Fake glue

**Scope:** `rust/crates/wormhole-sftp/src/prewarm.rs` (`SftpPrewarmGlue` /
`FakePrewarmedSftp` / `FakeShellTunnel` / `BorrowedShellTunnel` /
`FakePrewarmConnectMode` / `try_consume` / `finish_prewarm`), exports in
`lib.rs`, `Cargo.toml` description, `docs/migration/11-sftp.md` prewarm
section, feature-matrix SFTP pre-warm Lab row, interop-inventory SFTP note,
README ledger link; this ledger.

**Out of scope:** Live russh dial; wiring consumed pair into
`FileTransferDialogState`; C# `SshSessionViewModel` mutations; HardwarePass /
cutover; `wormhole-tunnels` dependency for borrow Fake.

**Compared against:** C# `SshSessionViewModel` prewarm (`StartPrewarm` /
`PrewarmAsync` / `TryConsumePrewarmedSftp` / `CancelAndDisposePrewarm` /
`BorrowTunnelForSftp`) + `BorrowedTunnelInstance` non-owning dispose.

**Authority:** full adversarial-review-fix (edit in scope; no child agents)  
**Baseline (pre-fix):** prior Fake glue + 16 prewarm unit tests green; disconnect
cleared Connected **then** cancelled in a second critical section  
**Final:** 66 lib + 12 `serialize_queue` = **78** passed; prewarm module **20**
unit tests.

Context7 MCP unavailable in this environment.

---

## Gate summary

| Gate | Result |
|---|---|
| Adversarial clean passes | **2** consecutive (independent attack order; re-established after fix + simplify delta) |
| Iterative-review-simplify clean passes | **3** consecutive |
| `cargo test -p wormhole-sftp` | **pass** (66 unit + 12 integration) |
| `git diff --check` (scoped) | **pass** |

---

## Accepted findings and fixes

| ID | Sev | Location | Invariant / evidence | Fix | Verification |
|---|---|---|---|---|---|
| PREWARM-01 | P2 | `BorrowedShellTunnel::dispose` | Drop after explicit `dispose` double-counted (C# Interlocked once) | Idempotent `AtomicBool` dispose gate | `borrow_dispose_is_idempotent` |
| PREWARM-02 | P3 | `FakePrewarmedSftp::Default` | Dead `id: 0` Default unused / confusing vs `new() -> Arc` | Remove `Default` | compile + suite |
| PREWARM-03 | P2 | `try_consume_drops_stale_session` | Weak `has_in_flight \|\| has_prewarmed` did not pin Deferred empty-cache rewarm | Assert in-flight && !prewarmed | that test |
| PREWARM-04 | P2 | tests | Retry after `ImmediateFail`, borrow idempotency unpinned | `retry_after_immediate_fail_can_warm`, `borrow_dispose_is_idempotent` | those tests |
| PREWARM-05 | P3 | module rustdoc / `11-sftp.md` | `ImmediateSuccess` sync-eager vs C# async empty-while-in-flight undocumented | Doc note + Deferred for timing pins | docs + Deferred tests |
| PREWARM-06 | P3 | `FakeShellTunnel::Default` | Non-`Arc` Default unused | Remove `Default` | compile |
| PREWARM-07 | P3 | `try_consume` | Status re-read after cache take (C# `Status == Connected`) should stay explicit | Use `is_ssh_connected()` after take (not snapshot-at-take) | suite |
| PREWARM-08 | P1 | `on_ssh_status(false)` | Cleared `ssh_connected` then `cancel_and_dispose` in a **second** lock → racing `on_ssh_status(true)` could leave Connected + empty (no in-flight / cache) | Clear Connected + take in-flight/cache under one lock | `disconnect_is_atomic_with_cache_clear`, `concurrent_status_flips_settle_consistently`, `reconnect_after_disconnect_rewarms` |
| PREWARM-09 | P2 | `begin_prewarm` ImmediateSuccess | `debug_assert!(stashed)` false under disconnect race (panic in test builds) | Drop assert; finish disposes on cancel race | concurrent stress + suite |
| PREWARM-10 | P3 | `begin_prewarm` Deferred/Fail | Borrowed shell tunnel then immediately Dropped unused | Borrow / clone shell Arc only for `ImmediateSuccess` | suite |
| PREWARM-11 | P3 | tests / docs | Reconnect rewarm + eager ImmediateSuccess rewarm + atomic disconnect undoc’d | Tests + `11-sftp.md` / module rustdoc | those tests + doc review |

### Simplify delta (post-adversarial)

| ID | Sev | Location | Change | Verification |
|---|---|---|---|---|
| S-01 | — | `try_consume` | Prefer `is_ssh_connected()` helper over duplicating lock reads | suite; adversarial re-looped |
| S-02 | — | `FakeShellTunnel` / `FakePrewarmedSftp` | Drop unused `Default` impls (overlap PREWARM-02/06) | suite |
| S-03 | — | `take_inflight_and_cache` | Share clear helper between disconnect path and `cancel_and_dispose` | suite; adversarial re-looped to 2 clean |

Production deltas from S-01 / S-03 / PREWARM-08..11 → adversarial re-looped to 2 clean.

---

## Rejected candidates

| Candidate | Reason |
|---|---|
| Make `try_consume` rewarm always Deferred under `ImmediateSuccess` | Sync-eager Fake is intentional; Deferred pins C# timing; documented + `try_consume_immediate_success_rewarm_is_eager` |
| Snapshot `ssh_connected` with cache take (one lock) | Regresses C# post-take `Status` re-read |
| Store real credential bytes on glue | C# silent flag only; secrets stay on SSH tab |
| Wire consumed pair into `FileTransferDialogState` | Documented host / follow-up |
| Depend on `wormhole-tunnels` for borrow | Keep local Fake (same pattern as `FakeTunnelSocks`) |
| Live russh / OTP tunnel establish | Out of scope (pure Fake) |
| Soften borrow Drop to close shell | Would burn OTP / tear down SSH tunnel — invariant |
| Validate every `PrewarmToken` uniqueness forever after wrap | Stub; skip-0 on wrap is enough |
| Collapse stale/live `try_consume` branches into one rewarm block | C# keeps separate arms; taste-only |
| Make `cancel_and_dispose` clear `ssh_connected` | C# cancel does not change Status; public cancel-while-Connected stays valid |
| Bound / soft-fail poisoned Mutex | Matches other Lab Fakes (`expect` on poison) |

---

## Adversarial clean passes (2 required)

Reset after each fix batch and after simplify deltas that touched implementation
(S-01 / S-03 / PREWARM-08..11).

### Clean pass 1 — order: concurrency → security → contract → boundaries → state → tests

- Atomic disconnect (Connected + slot clear one lock); token identity; late
  `finish_prewarm` after cancel fails closed; borrow dispose idempotent;
  concurrent status stress settles Connected+creds into warm/flight without
  shell `close`.
- `credentials_present` flag only; Debug omits password/secret/`hunter2`.
- Connected+creds start; disconnect cancel+dispose; consume once + rewarm;
  stale → None; borrow never closes shell.
- Foreign token / no creds / ImmediateFail / Deferred hang / reconnect covered.
- **Accepted findings:** none.

### Clean pass 2 — order: integration → operability → failure atomicity → security → contract → test resistance

- Exports / `11-sftp.md` / feature-matrix Lab / interop / README ledger aligned
  (atomic disconnect called out).
- Connect modes documented (ImmediateSuccess eager Fake vs Deferred timing).
- Cancel clears in-flight before/with Connected flip; finish under one lock
  (no half-stash); ImmediateSuccess finish may dispose on race (no assert).
- No secret material; public Debug whitelist.
- Concurrent flips + reconnect + eager rewarm + stale Deferred pins resist
  false greens.
- **Accepted findings:** none.

`adversarial_clean_passes = 2`.

---

## Iterative-review-simplify (3 clean cycles)

Each cycle: Code Reuse → Code Efficiency → Code Quality and Bugs (+ simplify
discipline).

| Cycle | Themes | Outcome |
|---|---|---|
| 1 (fix, historical) | Quality (`is_ssh_connected` helper; drop unused Defaults) | S-01/S-02 → counter reset |
| 1 (fix, this run) | Reuse (`take_inflight_and_cache`); efficiency (shell clone only ImmediateSuccess); quality (atomic disconnect) | S-03 / PREWARM-08..11 → adversarial renewed |
| 1 (clean) | Reuse (keep local borrow Fake; no tunnels dep); efficiency (single-lock finish); quality (idempotent dispose) | Clean |
| 2 | Reject snapshot-at-take / dialog wire / credential storage / try_consume branch collapse | Clean |
| 3 | Docs/matrix/interop parity; Deferred + concurrent + reconnect pins; no further validated churn | Clean |

`simplify_clean_passes = 3`. No further simplify implementation delta after the
last adversarial re-loop.

---

## Regression tests added/updated

**`src/prewarm.rs` unit (20)**
- borrow Drop / dispose never closes shell; dispose idempotent
- prewarm borrows shell without close; cancel disposes session not shell
- disconnect clears cache + in-flight; finish after cancel / foreign token
- try_consume none-before-ready; once + Deferred rewarm; ImmediateSuccess eager rewarm
- stale session dispose + Deferred rewarm; ImmediateFail empty; retry after fail
- no creds silent; begin idempotent while warm/in-flight
- Debug omits secret-shaped fields
- reconnect after disconnect rewarms
- disconnect atomic with cache clear
- concurrent status flips settle consistently (shell close_count == 0)

**Docs**
- `11-sftp.md` prewarm section (atomic disconnect)
- feature-matrix Lab row; interop-inventory SFTP note; README ledger index

---

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-sftp
cargo test -p wormhole-sftp --lib prewarm::
```

**Result (final):** 66 lib + 12 `serialize_queue` = **78 passed**; prewarm
module **20** unit tests.

## Gate confirmation

- Adversarial clean passes: **2** (independent orderings; renewed after
  PREWARM-08..11 / S-03).
- Iterative-review-simplify clean passes: **3**.
- No accepted non-blocked findings remain.
- Live russh dial / dialog consume wiring untouched (Pending).
- No commit / push (per request).
