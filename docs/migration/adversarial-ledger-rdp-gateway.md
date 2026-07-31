# Adversarial ledger — RDP gateway / tunnel policy

Scope: `rust/crates/wormhole-surface-win/src/rdp/configure.rs` helpers
`validate_rdp_gateway_tunnel_combo` / `validate_tunnel_rdp_policy` (+ related docs in
`docs/migration/05-rdp-spike.md`, README link)  
Out of scope: CredSSP password wipe paths (`WipePasswordOnDrop` / `ClearTextPassword`);
OLE/overlay hosting; full RD Gateway `TransportSettings2` apply; C# sources (read-only parity)  
Constraints: C# `RdpSessionViewModel` `TunnelEnabled && RdpGatewayUsageMethod != 0`;
priority External → Gateway → Strict; pure policy (no hardware / gate-6 lab claim)  
Baseline: `cargo test -p wormhole-surface-win --features rdp` green (106 tests) before review  
Design SoT: `docs/migration/05-rdp-spike.md`, AGENTS.md VPN routing notes, C# `ConnectionProfile.RdpGatewayUsageMethod`

## Findings

| ID | Sev | Location | Issue | Evidence | Disposition |
|---|---|---|---|---|---|
| GW-001 | P2 | `configure.rs` tests | Reject vectors omitted C# `3` (`DefaultRdg`) | `ConnectionProfile`: `0=Direct, 1=Always, 2=Detect, 3=DefaultRdg`; loops used `1,2,-1,MAX,MIN` only — a future `match 1\|2` could false-Ok `3` | **Fixed** — include `3` in nonzero vectors; docs cite enum |
| GW-002 | P2 | `configure.rs` tests | No delegation-identity pin between combo helper and full policy Gateway path | Policy calls combo today, but nothing asserted same `TunnelRdpConflict::Gateway` + `TUNNEL_GATEWAY_UNSUPPORTED` / `Display` | **Fixed** — `policy_gateway_err_matches_combo_helper_identity` |
| GW-003 | P2 | `05-rdp-spike.md` + rust docs | C# gateway enum + “pure policy / not hardware” under-documented; sample only showed usage `0`/`1` | Attack focus: Docs C# parity accurate; no hardware gate claim | **Fixed** — enum table, tunnel-off allow sample, explicit pure-policy note |
| GW-004 | P3 | `gateway_checked_before_strict_auth` | Only exercised usage `1` for gateway-before-strict | Priority regression for `2`/`3`/negatives/MAX not pinned | **Fixed** — loop `NONZERO_GATEWAY_METHODS` |
| GW-005 | P3 | tests | Duplicated gateway method arrays across tests | Drift risk across reject/allow/priority loops | **Fixed** — `NONZERO_GATEWAY_METHODS` / `ALL_GATEWAY_METHODS` |
| GW-006 | P3 | `tunnel_off_allows_all_combos` | Only one gateway method (`1`) with tunnel off | Attack focus “tunnel off always allows gateway” under-pinned for `0..=3` + extremes | **Fixed** — iterate `ALL_GATEWAY_METHODS` |
| GW-007 | — | Reorder Gateway before External | Would break C# connect-guard order (`ShouldUseExternalClient` then gateway) | Attack wording “gateway before other checks” means before **strict**, not before external | **Rejected** — External → Gateway → Strict retained; tests pin both |
| GW-008 | — | CredSSP / `WipePasswordOnDrop` | Out of scope | Grep — untouched this review | **Rejected** — out of scope |
| GW-009 | — | Closed enum match (`1\|2\|3` only) | Would false-Ok negatives / unknown ints | C# uses `!= 0` | **Rejected** — keep `!= 0` |

## Fixes applied

- `rdp/configure.rs` — C# enum docs on `gateway_usage_method` + combo/policy helpers; priority wording (gateway before strict; External still first); shared test vectors; method `3` + delegation identity + strengthened tunnel-off / gateway-before-strict tests
- `docs/migration/05-rdp-spike.md` — C# `RdpGatewayUsageMethod` values; pure-policy / not-hardware note; sample covers `0`/`3`/tunnel-off
- `docs/migration/README.md` — ledger link
- `docs/migration/adversarial-ledger-rdp-gateway.md` — this ledger

## Gate record

### Adversarial loop

| Cycle | Strategy | Accepted findings | Result |
|---|---|---|---|
| Adv-0 (initial) | Contract → boundary → state → concurrency → security → integration → perf → tests | GW-001…006 | Fixed; counter reset |
| Adv-1 | Same lanes on fixed tree; C# string byte-match; wipe paths untouched; no hardware claim | None | Clean (1/2) |
| Adv-2 | Reverse: tests-as-oracles → docs enum parity → `!= 0` vs closed match → External/Gateway/Strict priority → CredSSP wipe untouched | None | Clean (2/2) |

### Iterative-review-simplify (after adversarial clean)

| Cycle | Reuse | Efficiency | Quality/Bugs | Accepted | Result |
|---|---|---|---|---|---|
| Sim-fix | Duplicated gateway method arrays | — | tunnel-off only method `1` | **Fixed** shared consts + `ALL_GATEWAY_METHODS` tunnel-off loop | Reset |
| Sim-1 | Shared consts used by reject/allow/priority/identity | Pure helpers, no I/O | C# messages match; wipe untouched | None | Clean (1/3) |
| Sim-2 | Reject over-abstract `sample_policy` builder | No hot-path work | Docs match `!= 0` + enum | None | Clean (2/3) |
| Sim-3 | Policy still delegates to combo (single Gateway source) | Unit tests only | Gateway-before-strict + External-first pinned | None | Clean (3/3) |

### Adversarial re-loop (required after simplify edits)

| Cycle | Strategy | Accepted | Result |
|---|---|---|---|
| Adv-R1 | Delta: shared vectors include `3`+`MIN`; tunnel-off loop; identity test; docs pure-policy | None | Clean (1/2) |
| Adv-R2 | Reverse: C# `!= 0`, message strings, priority, no CredSSP wipe edits, no hardware gate claim | None | Clean (2/2) |

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-surface-win --features rdp
```

Result: **pass** — 107 unit tests with `--features rdp` (prior suite + `policy_gateway_err_matches_combo_helper_identity`).

## Residual notes

- Full RD Gateway apply (`TransportSettings2`) remains deferred; this ledger covers **reject policy** only.
- CredSSP password wipe was intentionally not modified.
- Session-layer wiring of these helpers into a future Rust connect path is still later work; helpers are exported from `wormhole_surface_win::rdp`.
  `wormhole-session` intentionally does **not** depend on `wormhole-surface-win` (COM/OLE surface crate); RDP stubs still fail closed with `UnsupportedProtocol` before establish. Do not duplicate gateway policy in session.

## Re-audit pin (2026-07-31)

**Verdict: already solid — docs-only; no Rust code change.**

| Check | Status |
|---|---|
| `validate_rdp_gateway_tunnel_combo(tunnel_on, usage != 0)` → `Err(Gateway)` | Present + unit-covered |
| `validate_tunnel_rdp_policy` External → Gateway → Strict | Present + unit-covered |
| `prepare_rdp_connect_target` policy **before** Fake bind / Connect | Present (`target.rs`) |
| Pure Rust / Fake; no live OCX | Held |
| Focused `cargo test -p wormhole-surface-win --features rdp -- gateway tunnel_rejects policy_gateway prepare_policy prepare_external prepare_strict` | **15 passed** |

**Parent: SKIP adversarial** — no intentional behavior change; prior Adv 2/2 + Sim 3/3 stand.
