# Adversarial ledger — tunnels / MCP / app bootstrap

**Scope:** `rust/crates/wormhole-tunnels`, `rust/crates/wormhole-mcp`, `rust/crates/wormhole-app`, `docs/migration/07-tunnels-mcp.md`  
**Authority:** adversarial-review-fix (edit in scope; no Go sidecars; no C# production mutations)  
**Baseline (pre-fix):** `cargo test -p wormhole-tunnels|mcp` and `cargo check -p wormhole-app` green (3 lease tests + 3 MCP tests).

---

## Accepted findings and fixes

| ID | Sev | Location | Invariant / evidence | Fix | Verification |
|---|---|---|---|---|---|
| T-01 | P0 | `manager.rs` `establish` | Drop/abort mid-`establish` never called release → pool ref leak; next connect stuck or double-OTP risk. C# releases on `WaitAsync` cancel. | `EstablishRefGuard` releases on Drop; lease path `disarm`s. | `drop_mid_establish_releases_refcount_and_cancels` |
| T-02 | P1 | `manager.rs` failure path | Failed shared future left joinable until a waiter ran Err (race). C# `EvictLocked` in establish core. | Evict inside shared future on provider Err / orphan. | `provider_failure_evicts_and_releases_all_waiters` |
| T-03 | P1 | `providers/mod.rs` stubs | Stubs returned `Up` + fake SOCKS — pretended live VPN. | Stubs return `TunnelError::NotImplemented`; tests use `FakeTunnelProvider`. | `production_stub_providers_do_not_pretend_live_vpn` |
| T-04 | P1 | `StubTunnelInstance::state` | `tokio::Mutex::try_lock` fallback to `Up` could hide `Failed`/`Closed` under contention. | `std::sync::Mutex` for state. | `failed_instance_gets_fresh_establish`, `closed_instance_gets_fresh_establish` |
| T-05 | P1 | lease tests gap | UpdatedAt / Failed / Closed / last-close not pinned. | Added regressions + `last_lease_closes_underlying_instance`. | lease_coalesce suite |
| T-06 | P2 | `EstablishSharedError` | `NotImplemented` stringified to `Establish` — contract loss; `"cancelled"` collision risk. | Typed shared error + `From` mappings. | stub test asserts `NotImplemented` via manager |
| T-07 | P2 | `wormhole-mcp` port / URL | Port `0` accepted; loopback contract only implicit. | `validate_mcp_port`, `loopback_endpoint_url`, `with_port` → `Result`. | `rejects_port_zero`, `endpoint_url_is_loopback_only` |
| T-08 | P2 | MCP tokens / logs | Approval token must never hit tracing. | Start logs endpoint only; regenerate documents no token log. | Review + lifecycle tests |
| T-09 | P2 | `wormhole-app` | No Arc/optional-dep smoke; `--no-default-features` `unused_mut`. | `tests/services_smoke.rs`; cfg-rebinding builder. | `cargo test -p wormhole-app`, `cargo check -p wormhole-app --no-default-features` |

---

## Rejected candidates

| Candidate | Reason |
|---|---|
| SOCKS liveness probe (C# `IsLoopbackEndpointAliveAsync`) | Skeleton has no real sidecar listener; deferred with real providers. |
| Secret blob zeroization | Out of scope until secrets crate wires establish. Stubs never log secrets. |
| `McpError::AlreadyRunning` / `NotRunning` unused | Reserved for real bind; start/stop intentionally idempotent like tolerant UX. |
| Sync Drop without tokio skips `close` | Documented warn; matches prior skeleton; leases normally release on runtime. |
| Cryptographically strong placeholder MCP tokens | Placeholder only; real token = Credential Manager later. |

---

## Adversarial clean passes (2 required)

### Clean pass 1 — order: concurrency → security → state → contract → tests

- Lease coalesce / last-release / cancel / orphan / failure eviction reviewed against `TunnelManager.cs`.
- Stubs NotImplemented; secrets absent from logs/errors; MCP loopback + port 0.
- **Accepted findings:** none.

### Clean pass 2 — order: integration → boundaries → test resistance → operability → security

- AppServices optional features / Arc cloning; MCP `rmcp` on/off; tunnels `domain` on/off.
- Boundary: duplicate providers, empty secret vec, UpdatedAt bump, Failed/Closed with outstanding lease.
- **Accepted findings:** none.

`adversarial_clean_passes = 2`.

---

## Iterative-review-simplify (3 clean cycles)

Each cycle: Code Reuse → Code Efficiency → Code Quality and Bugs (+ simplify discipline).

| Cycle | Themes | Outcome |
|---|---|---|
| 1 | Reuse (`is_unusable`, `loopback_endpoint_url`, `not_implemented`); efficiency (poll waits vs fixed sleeps); quality (typed errors already in) | No further validated edits |
| 2 | Reuse of Fake vs stub separation (keep intentional); Rmcp delegate boilerplate necessary; no hot-path issues in skeleton | Clean |
| 3 | Re-check cancel guard / poison recovery / docs parity with `07-tunnels-mcp.md` | Clean |

`simplify_clean_passes = 3`. No post-simplify implementation delta → adversarial remains at 2 clean.

---

## Regression tests added/updated

- `wormhole-tunnels/tests/lease_coalesce.rs` — 12 tests (coalesce, last release/close, reuse, UpdatedAt, Failed, Closed, drop mid-establish, provider failure, NotImplemented stubs, bind stub, duplicate providers).
- `wormhole-mcp/tests/host_lifecycle.rs` — port 0, loopback URL, idempotent start/stop, regenerate token, rmcp port 0.
- `wormhole-app/tests/services_smoke.rs` — default wiring, omit optionals, stub store ping.

---

## Final verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-tunnels
cargo test -p wormhole-mcp
cargo test -p wormhole-app
cargo check -p wormhole-app
cargo check -p wormhole-app --no-default-features
cargo check -p wormhole-mcp --no-default-features
cargo check -p wormhole-tunnels --no-default-features
```

Results: all green (recorded at ledger close).
