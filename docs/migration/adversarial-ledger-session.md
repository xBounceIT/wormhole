# Adversarial ledger — `wormhole-session`

Scope: `rust/crates/wormhole-session/`, `docs/migration/16-session-orchestrator.md`  
(App wiring in `wormhole-app` inspected; no session-wiring fix required.)  
Baseline: `cargo test -p wormhole-session` green (17 tests) before review  
Attack focus: Serial never tunnels; cancel races (Connecting→Closed); password never in Display/Debug; tunnel lease dispose on fail/cancel; UnsupportedProtocol for RDP/VNC; HTTP/HTTPS target correctness; state machine illegal transitions; SOCKS optional path.

## Findings

| ID | Sev | Location | Issue | Evidence | Disposition |
|---|---|---|---|---|---|
| S-SESSION-001 | P1 | `orchestrator.rs` `connect_inner` | RDP/VNC with `tunnel_enabled` established a lease (OTP/churn) before `UnsupportedProtocol` | Path: wants_tunnel → establish → then unsupported | **Fixed** — reject unsupported protocols before tunnel |
| S-SESSION-002 | P1 | tests | Fail/cancel after tunnel did not pin lease release (`pool_ref_count == 0`) | Impl released lease on Err; untested | **Fixed** — `cancel_after_tunnel_releases_lease`, `ssh_fail_after_tunnel_releases_lease`, `ssh_via_tunnel_without_socks_fails_and_releases_lease` |
| S-SESSION-003 | P2 | `connect_http` + tests | SOCKS-optional forwarder path untested; bind not cancellable | Branch existed; FakeTunnel always exposes SOCKS | **Fixed** — cancel/`select!` around forwarder bind; `https_via_tunnel_forwarder_when_no_socks` |
| S-SESSION-004 | P2 | cancel / state | Cancel must not leave `Connecting`; close only after Failed/Connected → Closed | Doc: Connecting→Connected\|Failed; close→Closed | **Fixed** — regression tests `cancel_then_close_is_failed_then_closed`, `cancel_during_slow_ssh` asserts not Connecting |
| S-SESSION-005 | P2 | `ConnectOptions` Debug | Password/secret redaction weakly pinned | Only Display of `PasswordRequired` covered | **Fixed** — `connect_options_debug_redacts_password` |
| S-SESSION-006 | P3 | tests | VNC unsupported + RDP-skips-tunnel + serial establish_count=0 + invalid SSH port unpinned | Partial coverage | **Fixed** — dedicated tests |
| S-SESSION-007 | — | Cancel → Closed directly | Suspected illegal Connecting→Closed on cancel | Cancel correctly lands Failed; Closed only via `close()` | **Rejected** — matches doc state table |
| S-SESSION-008 | — | Password word in `PasswordRequired` Display | Attack “password never in Display” | Message names the concept, not the secret value | **Rejected** — secret never interpolated |
| S-SESSION-009 | — | Credential resolve not in `select!` | Hang could ignore cancel | Instant resolvers; no reachable hang in scope | **Rejected** — speculative |
| S-SESSION-010 | — | App `session` wiring | DI / feature gate drift | `build_default_services` wires Live connectors + ManagerTunnelBroker | **Rejected** — no defect |

## Fixes applied

- `src/orchestrator.rs` — early UnsupportedProtocol; HTTP cancel + forwarder `select!`
- `src/connectors.rs` — `FakeTunnelBroker` exposes `provider()` / `manager()` for lease assertions
- `tests/orchestrator_fakes.rs` — attack-focus regressions (25 integration tests)
- `docs/migration/16-session-orchestrator.md` — cancel/tunnel/unsupported notes + ledger link
- Simplify: drop unused `with_provider`; RDP/VNC dispatch arm → `unreachable!`; trim unused test counters

## Gate record

### Adversarial loop (post-fix)

| Cycle | Strategy | Accepted findings | Result |
|---|---|---|---|
| Adv-fix | Contract → boundary → state → concurrency → security → integration → perf → tests | S-SESSION-001…006 | Fixed; counter reset |
| Adv-1 (post-fix) | Re-attack all lanes on updated impl | None | Clean (1/2) |
| Simplify batch | Reuse / efficiency / quality | Dead `with_provider`, unused counters, duplicate Err arm | Fixed; **adversarial reset** |
| Adv-1′ (post-simplify) | Tests-as-oracles → lease dispose → cancel state → serial/no-tunnel → early RDP | None | Clean (1/2) |
| Adv-2′ | Reverse: security/PII Debug → SOCKS optional → HTTP targets → state machine illegal transitions | None | Clean (2/2) |

### Iterative-review-simplify (after adversarial clean)

| Cycle | Reuse | Efficiency | Quality/Bugs | Accepted | Result |
|---|---|---|---|---|---|
| Sim-1 | Early unsupported + exhaustive match kept (clear) | No hot-path I/O | `unreachable!` only after typed reject | None | Clean (1/3) |
| Sim-2 | Fake broker mirrors manager API; no extra abstraction | Cancel checks cheap | Redaction + lease tests sufficient | None | Clean (2/3) |
| Sim-3 | Forwarder-only double lives in tests only | Profile clone once per connect | Docs/tests aligned; diff in-scope | None | Clean (3/3) |

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-session
```

Result: **pass** (27 tests: 2 profile unit + 25 orchestrator fakes).
