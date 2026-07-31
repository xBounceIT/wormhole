# Adversarial ledger — `wormhole-session` RDP/VNC stubs

Scope: `rust/crates/wormhole-session/src/rdp_vnc.rs`, orchestrator early-reject path for RDP/VNC, `StubRdpConnector` / `StubVncConnector`, `docs/migration/16-session-orchestrator.md`  
Baseline: `cargo test -p wormhole-session` green (35 tests: 8 unit + 27 orchestrator) before review  
Attack focus: reject **before** tunnel; `UnsupportedProtocol` structured reason; no COM; passwords not in `Debug` of requests; invalid port fail-closed.

## Findings

| ID | Sev | Location | Issue | Evidence | Disposition |
|---|---|---|---|---|---|
| SRV-RDPVNC-001 | P2 | `rdp_vnc.rs` + orchestrator tests | Boundary fail-closed under-tested: negative/overflow ports, empty/whitespace host, VNC zero-port, invalid-port+tunnel (no establish) | Only RDP port `0` pinned; tunnel skip only covered happy UnsupportedProtocol path | **Fixed** — unit + orchestrator regressions |
| SRV-RDPVNC-002 | P2 | `RdpConnectRequest` / `VncConnectRequest` Debug | Password-not-in-Debug contract unpinned; requests omit secrets only by field absence | No test that planted profile/ConnectOptions secrets stay out of request/error `Debug`/`Display` | **Fixed** — docs on structs + unit/orchestrator redaction tests |
| SRV-RDPVNC-003 | P3 | `try_from_profile` | Wrong-protocol prepare untested | Direct API could return wrong `Other` shape unnoticed | **Fixed** — `rejects_wrong_protocol` |
| SRV-RDPVNC-004 | — | Cancel before stub prepare | Cancelled token returns `Cancelled` without prepared request | `check_cancel` before RDP/VNC arms | **Rejected** — cancel priority matches orchestrator contract |
| SRV-RDPVNC-005 | — | ZWSP-only host | Non-trimmable Unicode accepted as host | Speculative; not in attack criteria | **Rejected** — speculative |
| SRV-RDPVNC-006 | — | VNC invalid-port+tunnel matrix | Only RDP overflow+tunnel + VNC empty-host+tunnel | Same early-return arms; covered by shared prepare | **Rejected** — duplicate of SRV-RDPVNC-001 coverage |

## Fixes applied

- `src/rdp_vnc.rs` — secret-free request docs; boundary + Debug redaction + wrong-protocol unit tests; `Stub*Connector::connect` returns `SessionError` directly (no `Result<Infallible>` dance)
- `src/orchestrator.rs` — `Err(Stub*Connector::connect(request))` after prepare
- `tests/orchestrator_fakes.rs` — VNC invalid port; RDP invalid-port skips tunnel; VNC empty host skips tunnel; UnsupportedProtocol Debug omits ConnectOptions password
- `docs/migration/16-session-orchestrator.md` — link this ledger

## Gate record

### Adversarial loop (post-fix)

| Cycle | Strategy | Accepted findings | Result |
|---|---|---|---|
| Adv-fix | Contract → boundary → state → concurrency → security → integration → perf → tests | SRV-RDPVNC-001…003 | Fixed; counter reset |
| Adv-1 | Re-attack all lanes on updated stubs | None | Clean (1/2) |
| Adv-2 | Reverse: Debug/PII → invalid port → no COM → reject-before-tunnel → structured reason → test oracles | None (004–006 rejected) | Clean (2/2) |
| Simplify batch | Reuse / efficiency / quality | `connect` → `SessionError` | Fixed; **adversarial reset** |
| Adv-R1 (post-simplify) | Delta: SessionError connect + prior invariants | None | Clean (1/2) |
| Adv-R2 | Reverse: stronger fail-closed API, secrets, tunnel skip, COM absence | None | Clean (2/2) |

### Iterative-review-simplify (after adversarial clean)

| Cycle | Reuse | Efficiency | Quality/Bugs | Accepted | Result |
|---|---|---|---|---|---|
| Sim-fix | — | — | `Result<Infallible>` awkward vs always-fail stub | **Fixed** connect API | Reset |
| Sim-1 | Shared `validate_port`/`normalize_host` kept; no trait over-abstract | No stub I/O | Direct `Err(connect(...))` clear | None | Clean (1/3) |
| Sim-2 | Static stubs (not DI) intentional | Profile clone micro-cost rejected | Redaction + tunnel-skip tests sufficient | None | Clean (2/3) |
| Sim-3 | Prepare-then-connect two-step kept for UI branching | Hot path N/A | Docs/tests aligned; in-scope diff | None | Clean (3/3) |

No adversarial findings after the simplify batch → simplify not re-run.

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-session
```

Result: **pass** (43 tests: 12 unit + 31 orchestrator fakes).
