# Adversarial ledger — SOCKS5 + LocalForwarder

**Scope:** `rust/crates/wormhole-tunnels/` (`socks5.rs`, `forwarder.rs`, `TunnelInstance` wiring via `bind_local_forwarder_for`), `docs/migration/07-tunnels-mcp.md` forwarder section  
**Authority:** adversarial-review-fix (edit in scope; no C# mutations; do not regress lease/sidecar fixes)  
**Preserved:** `EstablishRefGuard` / lease coalesce / sidecar control-plane tests unchanged and green  
**Baseline (pre-fix):** `cargo test -p wormhole-tunnels` green (60 lib unit tests before this pass)

---

## Accepted findings and fixes

| ID | Sev | Location | Invariant / evidence | Fix | Verification |
|---|---|---|---|---|---|
| F-01 | P1 | `forwarder.rs` `LocalForwarder` | Dropping without `shutdown` detached the accept `JoinHandle` → orphaned `127.0.0.1` listener | `Drop`: signal watch + abort accept; `accept_task: Option` for take-under-Drop | `local_forwarder_drop_aborts_accept_loop` |
| F-02 | P1 | `forwarder.rs` bridges | Bridge tasks spawned without tracking; shutdown left them detached (attack: “don't leak tasks”) | `Arc<StdMutex<Vec<JoinHandle>>>`; abort on `shutdown`/`Drop`; reap finished on push | bridge + shutdown tests; suite green |
| F-03 | P1 | `forwarder.rs` Drop vs bridges | Abort of accept is async — late `bridges.push` after drain could detach | Spin-yield until accept finished (≤200ms) before `abort_bridges` | drop test still passes |
| F-04 | P1 | `socks5.rs` encode | Bracketed IPv6 (`[2001:db8::10]`) failed `IpAddr` parse and risked IDNA path; C# `IPAddress.TryParse` accepts brackets | `unbracket_ipv6_literal` before parse | `connect_accepts_bracketed_ipv6` |
| F-05 | P2 | `socks5` / `forwarder` | Empty host / port `0` validated but untested; registry could look up before fail-closed | Shared `validate_target`; call from connect / start / `bind_or_reuse`; regressions | empty/port0 unit tests |
| F-06 | P2 | `socks5.rs` | Auth methods other than no-auth, truncated replies, unknown ATYP, IDN unpinned | Reject non-`0x00` method; `read_exact` errors; Punycode path; focused tests | auth / truncated / ATYP / IDN tests |
| F-07 | P2 | `forwarder.rs` bind | Must never bind non-loopback | Hardcoded `127.0.0.1:0` + post-bind `is_loopback` refuse | `local_forwarder_binds_loopback_only` |
| F-08 | P2 | `forwarder.rs` registry | Nested stale-replace + dead “concurrent race” block while lock held across start | Loop replace-stale; single bind under lock (C# gate parity) | `registry_concurrent_same_target_reuses_one_port` |
| F-09 | P3 | `forwarder.rs` bridges mutex | `if let Ok` on poison skipped abort → possible detach | `unwrap_or_else(into_inner)` on push + abort | code inspection + suite |

---

## Rejected candidates

| Candidate | Reason |
|---|---|
| Rewrite bridge as C# `WhenAny` + force-close | `copy_bidirectional` already half-closes write on EOF; behavior parity adequate |
| Check RSV byte in CONNECT reply | C# also ignores; not a contract violation |
| Cancel token on `Socks5Client::connect` | Out of API scope; task abort cancels at await points |
| Unicode case-fold host keys beyond ASCII | C# uses OrdinalIgnoreCase; ASCII-insensitive match matches current RDP/VNC targets; expanding is product scope |
| Fail locate / mutate lease or sidecar modules | Explicitly out of scope; lease + sidecar suites left green |
| Busy-loop if watch sender drops without `true` | Unreachable: `Drop`/`shutdown` always `send(true)` before releasing sender |

---

## Adversarial clean passes (2 required)

### Clean pass 1 — order: concurrency → security → state → contract → tests

- Registry lock serializes same-target bind; concurrent 16-way reuse pinned; stale crash replace loops safely.
- Loopback-only bind; no-auth only; empty/port 0 fail closed; bridges aborted on dispose.
- `TunnelUnavailable` / `NoSocksEndpoint` via `bind_local_forwarder_for`; lease suite untouched.
- **Accepted findings:** none.

### Clean pass 2 — order: integration → boundaries → test resistance → operability → security

- `StubTunnelInstance` / `SidecarTunnelInstance` still delegate to `bind_local_forwarder_for`.
- Boundaries: bracketed IPv6, IDN Punycode, truncated greeting/bound, unknown ATYP, method `0x02`/`0xFF`, oversized DOMAINNAME.
- Operability: shutdown stops accept; Drop does not orphan listener; half-close via `copy_bidirectional`.
- **Accepted findings:** none.

`adversarial_clean_passes = 2` (after post-simplify re-loop on the simplify delta; no further implementation findings).

---

## Iterative-review-simplify (3 clean cycles)

Each cycle: Code Reuse → Code Efficiency → Code Quality and Bugs (+ simplify discipline).

| Cycle | Themes | Outcome |
|---|---|---|
| 1 | Reuse (`validate_target`); efficiency (removed nested stale / dead race arm); quality (poison `into_inner`, Drop/accept ordering) | Applied → reset adversarial → re-looped to 2 clean |
| 2 | Removed redundant `let socks = socks`; dropped unused bound-addr IP constructions; docs forwarder table updated | Clean after verify |
| 3 | Lease/sidecar untouched; no further validated churn in socks5/forwarder | Clean |

`simplify_clean_passes = 3`.

---

## Regression tests added/updated

**`socks5.rs` unit**
- bracketed IPv6, IDN Punycode, empty host / port 0, non-no-auth + `0xFF`, truncated CONNECT reply, truncated bound IPv4, unknown ATYP, oversized hostname, `validate_target`

**`forwarder.rs` unit**
- loopback bind, empty/port 0, shutdown stops accept, Drop aborts accept, registry empty/port 0, concurrent same-target reuse, `bind_local_forwarder_for` unavailable states

**Unchanged green**
- `tests/lease_coalesce.rs` (incl. bind reuse)
- `tests/sidecar_control_plane.rs`

---

## Final verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd C:\Users\dange\.cursor\worktrees\wormhole\7mi5\rust
cargo test -p wormhole-tunnels
```

Results: **77** lib + **15** lease + **24** sidecar control-plane = all green.
