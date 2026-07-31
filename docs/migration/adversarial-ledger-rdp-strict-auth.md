# Adversarial ledger — RDP tunnel + strict server-auth policy

Scope: `rust/crates/wormhole-surface-win/src/rdp/configure.rs` tunnel policy helpers
(`validate_tunnel_rdp_policy` / `TunnelRdpPolicy` / `TunnelRdpConflict::StrictServerAuth` /
`TUNNEL_STRICT_SERVER_AUTH_UNSUPPORTED`) + focused tests/helpers; docs in
`docs/migration/05-rdp-spike.md` + README ledger link  
Out of scope: CredSSP password wipe (`WipePasswordOnDrop` / `ClearTextPassword` / Zeroizing
put path); OLE/overlay hosting; RD Gateway `TransportSettings2` apply; C# sources (read-only
parity)  
Constraints / attack focus:
- Only `server_authentication == 1` (Require) rejects with tunnel
- `0` / `2` / `3` / `-1` / `i32::MAX` / `i32::MIN` allowed with tunnel
- Message identity with C# `TunnelStrictServerAuthUnsupportedMessage`
- Priority vs gateway/external unchanged (External → Gateway → Strict)
- No hardware / gate-6 lab claim  
Baseline: `cargo test -p wormhole-surface-win --features rdp` green (107 tests) before review  
Design SoT: `docs/migration/05-rdp-spike.md`, AGENTS.md VPN routing notes, C#
`RdpSessionViewModel` connect guards + `ConnectionProfile.RdpServerAuthentication`

## Findings

| ID | Sev | Location | Issue | Evidence | Disposition |
|---|---|---|---|---|---|
| SA-001 | P2 | `configure.rs` tests | Strict-auth message only asserted against Rust const, not C# literal | `tunnel_rejects_strict_server_auth` used `assert_eq!(…, TUNNEL_STRICT_SERVER_AUTH_UNSUPPORTED)` — editing the Rust const alone would still pass; attack requires identity with C# `TunnelStrictServerAuthUnsupportedMessage` | **Fixed** — `CSHARP_TUNNEL_STRICT_SERVER_AUTH_UNSUPPORTED` + `strict_server_auth_message_matches_csharp_constant`; reject path also asserts `to_string()` against C# text |
| SA-002 | P2 | `configure.rs` tests | External-before-Strict with gateway Direct (`0`) not pinned | `external_checked_before_gateway` only used `gateway_usage_method: 2` + strict — a Strict-before-External reorder with Direct gateway would still look green | **Fixed** — `external_checked_before_strict_auth` (gateway `0`, external + Require → `ExternalClient`) |
| SA-003 | P3 | `tunnel_allows_non_require_server_auth` | Allow-loop alone does not prove Require still rejects in the same fixture family | Empty/`is_ok`-only loops can pass for the wrong reason if Require regresses elsewhere | **Fixed** — Require=`1` control `expect_err` in the same test; docs list explicit `0/2/3/-1/MAX/MIN` vectors |
| SA-004 | P3 | `05-rdp-spike.md` | Strict message / External-over-Strict / non-gate-6 wording under-specified vs attack | Gateway ledger covered gateway; strict-auth delta needed C# constant names + “not gate-6 hardware” | **Fixed** — cite C# message names; External wins over Strict even when gateway Direct; pure-policy / not gate-6 lab |
| SA-005 | — | Closed allow-list (`0\|2` only) for server auth | Would false-reject unknowns (`3`/`-1`/`MAX`/`MIN`) | C# uses `== 1`; `NON_REQUIRE_SERVER_AUTH` already includes attack vectors | **Rejected** — keep `== 1`; tests pin allow vectors |
| SA-006 | — | CredSSP / `WipePasswordOnDrop` | Out of scope | Diff / review — wipe paths untouched | **Rejected** — out of scope |
| SA-007 | — | Treat tunnel policy as gate-6 hardware requirement | Attack: no hardware gate claim | Docs state pure policy + unit tests only; gate-6 list remains OLE/overlay | **Rejected** — invariant held; wording strengthened (SA-004) |
| SA-008 | — | Reorder Gateway before External | Would break C# `ShouldUseExternalClient` then gateway then strict | Existing External-first + new External-before-Strict pins | **Rejected** — External → Gateway → Strict retained |

## Fixes applied

- `rdp/configure.rs` — C# message pin const + identity test; External-before-Strict (gateway `0`); Require control inside non-Require allow test; gateway-before-strict asserts `!= StrictServerAuth`
- `docs/migration/05-rdp-spike.md` — explicit allow vectors; C# message constant names; External wins over Strict with Direct gateway; not-a-gate-6 note
- `docs/migration/README.md` — ledger link
- `docs/migration/adversarial-ledger-rdp-strict-auth.md` — this ledger

## Gate record

### Adversarial loop

| Cycle | Strategy | Accepted findings | Result |
|---|---|---|---|
| Adv-0 (initial) | Contract → boundary → state → concurrency → security → integration → perf → tests | SA-001…004 | Fixed; counter reset |
| Adv-1 | Same lanes on fixed tree; C# string byte-match; wipe paths untouched; External/Gateway/Strict priority; `== 1` only; no hardware claim | None | Clean (1/2) |
| Adv-2 | Reverse: tests-as-oracles → docs C# names / allow vectors → `== 1` vs closed allow-list → External-before-Strict (gateway 0) → CredSSP wipe untouched → gate-6 non-claim | None | Clean (2/2) |

### Iterative-review-simplify (after adversarial clean)

| Cycle | Reuse | Efficiency | Quality/Bugs | Accepted | Result |
|---|---|---|---|---|---|
| Sim-1 | C# pin const shared by identity + reject tests; reject merging identity into reject-only | Pure helpers, no I/O | Reject removing `assert_ne!(Strict…)` after `assert_eq!(External…)` (taste) | None | Clean (1/3) |
| Sim-2 | Reject over-abstract `sample_policy` builder for three fixtures | Unit tests only | Docs match `== 1` + External→Gateway→Strict; wipe untouched | None | Clean (2/3) |
| Sim-3 | `NON_REQUIRE_SERVER_AUTH` single source for allow vectors | No hot-path work | Require control in allow test retained (anti-false-pass); exports unchanged | None | Clean (3/3) |

No simplify edits → adversarial re-loop not required (counter remains 2/2 from Adv-1/Adv-2).

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-surface-win --features rdp
```

Result: **pass** — 109 unit tests with `--features rdp` (prior 107 + `strict_server_auth_message_matches_csharp_constant` + `external_checked_before_strict_auth`).

## Residual notes

- `prepare_rdp_connect_target` already runs `validate_tunnel_rdp_policy` before Fake bind / Connect. Session-orchestrator wiring (and route-prompt “connect directly” relaxing Require) remains later work; `wormhole-session` intentionally does **not** depend on `wormhole-surface-win`. Helpers stay exported from `wormhole_surface_win::rdp`.
- CredSSP password wipe was intentionally not modified.
- Full RD Gateway apply remains deferred; this ledger covers **strict server-auth reject policy** (and its priority relative to External/Gateway). External/mstsc and gateway reject share the same `configure.rs` helpers — see sibling ledgers; do not fork a second policy path.

## Re-audit pin (2026-07-31)

**Verdict: already solid — docs-only; no Rust code change.**

| Check | Status |
|---|---|
| `server_authentication == 1` only → `Err(StrictServerAuth)` | Present + unit-covered |
| Non-Require allow vectors `0/2/3/-1/MAX/MIN` + Require control | Present (`NON_REQUIRE_SERVER_AUTH`) |
| C# `TunnelStrictServerAuthUnsupportedMessage` identity pin | Present |
| Priority External → Gateway → Strict (External-before-Strict w/ gateway `0`) | Present + unit-covered |
| `prepare_rdp_connect_target` strict reject **before** Fake bind | Present (`target.rs`) |
| Pure Rust / Fake; no live OCX / no HardwarePass | Held |
| Focused `cargo test -p wormhole-surface-win --features rdp -- strict_server_auth tunnel_rejects_strict tunnel_allows_non_require external_checked_before_strict gateway_checked_before_strict prepare_policy_strict prepare_external_before_socks prepare_policy_before_socks` | **8 passed** |

**Parent: SKIP adversarial** — no intentional behavior change; prior Adv 2/2 + Sim 3/3 stand. Shared file `configure.rs` coordinated with gateway re-audit (docs-only there too); no mstsc/external fork.
