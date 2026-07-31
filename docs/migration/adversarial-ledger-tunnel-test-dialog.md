# Adversarial ledger — Tunnel test dialog Fake VM glue (`wormhole-ui`)

**Scope:**
- `rust/crates/wormhole-ui/src/tunnel_test_dialog.rs` (+ crate-root re-exports / `tunnels` feature deps in `lib.rs` / `Cargo.toml`)
- Composes `wormhole-tunnels` (`TunnelManager`, `FakeTunnelProvider`, `FakeTunnelConfigLookup`, `FakeTunnelSecretLookup`) + `wormhole-session::describe_tunnel_phase`
- Docs: `07-tunnels-mcp.md` (test dialog section), `08-ui.md` cross-ref, `feature-matrix.md` (Tunnels UI row), `README.md` index
- this ledger

**Out of scope:** C# `TunnelTestDialog.xaml` / GPUI chrome; live sidecar spawn; DPAPI payload I/O; Stormshield typed recoverable exceptions (lab uses `NOTICE:title|message` prefix); live SOCKS `DialAsync`.

**Compared against:** C# `TunnelTestDialogViewModel` prepare → run → progress log → success/fail/cancel/informational → lease dispose  
**Authority:** full adversarial-review-fix (edit in scope)  
**Gates:** 2 clean adversarial cycles + 3 clean iterative-review-simplify cycles

## Baseline

- Before review: tunnel configs page/picker VM only; feature-matrix listed test dialog as Pending
- Attack focus: fail-closed probe validation; missing/empty secret before provider; lease drop closes diagnostic tunnel; cancel during delayed establish; informational vs failure; no secrets in VM `Debug` / establish error sanitize; invalid probe leaves `is_busy` false

## Findings

| ID | Sev | Location | Issue | Evidence | Disposition |
|---|---|---|---|---|---|
| TTD-001 | P1 | `run` probe validation early return | `is_busy` stayed true after invalid target | State machine leak | **Fixed** — clear busy + cancel slot + regression |
| TTD-002 | P2 | `From<TunnelError>` | `Establish` double-wrapped broke `NOTICE:` classification | informational test failed | **Fixed** — match `Establish(msg)` directly + strip prefix fallback |
| TTD-003 | P2 | `TunnelTestDialogVm::Debug` | Must not echo log secret material | Task invariant | **Fixed** — counts-only `Debug` + regression |
| TTD-004 | P2 | `sanitize_establish_message` | Secret-shaped establish errors could echo key material | Security lane | **Fixed** — redact `private_key` shapes |
| TTD-005 | P2 | `establish_config` | Cancel during `FakeTunnelProvider` delay must fail closed | C# cancel test parity | **Fixed** — `tokio::select!` + regressions |
| TTD-006 | P2 | `FakeTunnelTargetProbe::Debug` | Must not echo dial host on failure path | Fake Debug policy | **Fixed** — counts/flags only |
| TTD-007 | P2 | `request_cancel_for_close` | Host close mid-run needs concurrent cancel slot | C# `RequestCancelForClose` | **Fixed** — `Arc<Mutex<Option<CancellationToken>>>` + VM cancel test |
| TTD-008 | P3 | docs | Ledger + README + feature-matrix + `07`/`08` sections | Policy | **Fixed** — this ledger + doc updates |
| TTD-R1 | — | Live SOCKS probe in lab | Requires sidecar listener | Explicit Fake probe scope | **Rejected** |
| TTD-R2 | — | GPUI dialog chrome | Lab VM-only | **Rejected** |
| TTD-R3 | — | Stormshield exception types in Rust | Use `NOTICE:` prefix for lab | **Rejected** — documented |
| TTD-R4 | — | Merge into `wormhole-tunnels` | UI VM belongs in `wormhole-ui` | **Rejected** |
| TTD-R5 | — | Progress callbacks from provider | Fake provider has no IProgress; VM reports StartingTunnel | **Rejected** — C# parity sufficient for lab |

## Fixes applied

- `tunnel_test_dialog.rs` — `TunnelTestDialogVm`, `FakeTunnelTestLab`, `FakeTunnelTargetProbe`, `TunnelTargetProbe`, 13 regressions
- `lib.rs` / `Cargo.toml` — `tunnels` feature adds `tokio-util`, `async-trait`, `session`; re-exports
- `docs/migration/07-tunnels-mcp.md` — test dialog behaviour + verification
- `docs/migration/08-ui.md` — cross-ref
- `docs/migration/feature-matrix.md` — Tunnels UI row (test dialog Lab)
- `docs/migration/README.md` — index row
- `docs/migration/adversarial-ledger-tunnel-test-dialog.md` — this ledger

## Gate record

### Adversarial loop

| Cycle | Strategy | Accepted findings | Result |
|---|---|---|---|
| Adv-0 | Contract → boundary → state (busy/cancel) → security (Debug/sanitize) → integration (manager Fake) | TTD-001…008 | Fixed; reset |
| Adv-1 | Reverse: tests-as-oracles → probe host/port → informational prefix → cancel race | None (TTD-R1…R5 rejected) | Clean (1/2) |
| Adv-2 | Forward: success + probe + missing secret + provider failure last-step | None | Clean (2/2) |

### Iterative-review-simplify

| Cycle | Reuse | Efficiency | Quality/Bugs | Accepted | Result |
|---|---|---|---|---|---|
| Sim-1 | Reuse `TunnelManager` + Fake lookups; `describe_tunnel_phase` from session | Single module behind `tunnels` | TTD-001 busy leak; TTD-002 NOTICE mapping | **Fixed** → reset adv |
| Sim-2 | Shared cancel `Arc` slot; probe trait thin | No GPUI / sidecar deps | Unused imports trimmed | None | Clean (1/3) |
| Sim-3 | VM `Debug` counts-only; informational parser helper | Ledger + verification commands | None | None | Clean (2/3) |
| Sim-4 | No further extraction | Diff hygiene | None | None | Clean (3/3) |

Post-simplify adversarial re-run (Adv-1/Adv-2 after Sim-1): no new accepted findings.

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-ui --lib tunnel_test
```

**Result (final):** `tunnel_test` **13** passed; 0 failed.

```powershell
git diff --check -- rust/crates/wormhole-ui/src/tunnel_test_dialog.rs rust/crates/wormhole-ui/src/lib.rs rust/crates/wormhole-ui/Cargo.toml docs/migration/adversarial-ledger-tunnel-test-dialog.md docs/migration/07-tunnels-mcp.md docs/migration/08-ui.md docs/migration/README.md docs/migration/feature-matrix.md
```

**Diff hygiene:** clean (no whitespace errors on scoped paths).

## Gate confirmation

- Adversarial clean passes: **2** (Adv-1 / Adv-2).
- Iterative-review-simplify clean passes: **3**.
- No accepted non-blocked findings remain.
- No live VPN / GPUI / DPAPI churn.
