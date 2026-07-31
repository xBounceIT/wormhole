# Adversarial ledger — RDP `select_rdp_connect_target` / LocalForwarder stub

**Scope:** `rust/crates/wormhole-surface-win/src/rdp/target.rs` (+ `rdp/mod.rs` re-exports already present),
`docs/migration/05-rdp-spike.md` BindLocalForwarder section, README ledger link  
**Authority:** adversarial-review-fix (edit in scope)  
**Out of scope:** CredSSP password wipe / `WipePasswordOnDrop` / `ClearTextPassword` / Connect;
OLE/overlay hosting; live `wormhole-tunnels` bind; C# sources (read-only parity)  
**Baseline (pre-fix):** `cargo test -p wormhole-surface-win --features rdp` **126** passed  
**Final:** **135** passed (target module **26** tests)

Attack focus:

- Tunnel on → `LocalForwarder` only (never SOCKS)
- Policy (external / gateway / strict) runs **before** bind
- `SocksNotSupported` for mistaken SOCKS path
- `FakeTunnelForwarder` no network; fail-closed bind
- Docs accurate; no hardware / gate-6 claim

Context7 MCP unavailable in this environment.

---

## Findings

| ID | Sev | Location | Issue | Evidence | Disposition |
|---|---|---|---|---|---|
| RDF-001 | P2 | `target.rs` tests | “Never SOCKS” under-pinned (trait omits SOCKS but no exhaustive LocalForwarder-only pin) | Attack: tunnel on → LocalForwarder only; VNC parity `tunnel_present_is_local_forwarder_never_socks_variant` | **Fixed** — same exhaustive match + `prepare_allows_forwarder` LocalForwarder arm |
| RDF-002 | P2 | `target.rs` tests | Direct-path empty/whitespace/zero-port only covered with tunnel present | `rejects_empty_*` used `Some(&fake)` only | **Fixed** — `direct_rejects_empty_host_and_zero_port_without_tunnel` |
| RDF-003 | P2 | `select_rdp_connect_target` | Defense-in-depth `local_port == 0` after bind untested | Hostile `Ok(0)` trait impl | **Fixed** — `OkZeroPortForwarder` + `hostile_ok_zero_forwarder_port_fail_closed` |
| RDF-004 | P3 | tests | Trim-on-tunnel-path / IPv6 host preservation unpinned | Only Direct trim; no IPv6/bracketed bind assert | **Fixed** — `tunnel_path_binds_trimmed_host`, `ipv6_and_bracketed_host_preserved_on_forwarder_path` |
| RDF-005 | P3 | `target.rs` | Inline `Ipv4Addr::LOCALHOST.to_string()` could drift from C# loopback literal | VNC pin `LOOPBACK_HOST` | **Fixed** — `LOOPBACK_HOST` + `loopback_host_matches_ipv4_localhost` |
| RDF-006 | P3 | `05-rdp-spike.md` | Fail-closed table + “not hardware/gate-6” soft on target stub | Attack: docs accurate; no hardware claim | **Fixed** — fail-closed table; pure dial-target / not gate-6 note; Fake no-socket note |
| RDF-007 | P3 | tests / prepare | Gateway-before-bind only method `1`; External-before-SOCKS unpinned | C# `!= 0` includes `3`/extremes; External wins over SOCKS | **Fixed** — `NONZERO_GATEWAY` loop; `prepare_external_before_socks_reject` |
| RDF-008 | P3 | tests | Bind-failure Display / `Error::source` under-pinned | Secret-shaped Display; Policy vs Socks source | **Fixed** — `forwarder_bind_failed_display_is_non_secret`; `prepare_socks_reject_source_is_none` |
| RDF-009 | — | `tunnel_enabled` + `tunnel: None` → Direct | Caller footgun | C# Establish returns null only when tunnel off; session wiring deferred | **Rejected** — stub API keeps policy orthogonal to lease Option |
| RDF-010 | — | Share `normalize_host` / gateway vectors with VNC or configure | Duplicated helpers | Different error types / `cfg(test)` privacy | **Rejected** — cross-module churn out of scope |
| RDF-011 | — | Public `LocalForwarder.connect_host` forgeable | Manual enum construction | Speculative; `select_*` always sets loopback | **Rejected** — same as VNC |
| RDF-012 | — | CredSSP / `WipePasswordOnDrop` / Connect | Explicitly out of scope | Diff — configure/ocx wipe paths untouched | **Rejected** — out of scope |

---

## Fixes applied

- `rdp/target.rs` — `LOOPBACK_HOST`; stronger bind-failure match; regression tests for SOCKS-absence exhaustiveness, Direct boundaries, hostile `Ok(0)`, trim-on-bind, IPv6/bracketed hosts, Display non-secret, loopback pin, gateway nonzero loop, External-before-SOCKS, Error::source
- `docs/migration/05-rdp-spike.md` — fail-closed validation table; pure dial-target / not-hardware / not-gate-6; Fake no-socket; ledger link
- `docs/migration/README.md` — ledger index entry
- `docs/migration/adversarial-ledger-rdp-forwarder.md` — this ledger

---

## Gate record

### Adversarial loop

| Cycle | Strategy | Accepted findings | Result |
|---|---|---|---|
| Adv-0 (initial) | Contract → boundary → state → concurrency → security → integration → perf → tests | RDF-001…008 | Fixed; counter reset |
| Adv-1 | Same lanes on fixed tree; CredSSP wipe untouched; no hardware claim; policy before bind; Fake no network | None | Clean (1/2) |
| Adv-2 | Reverse: tests-as-oracles → SOCKS absence exhaustiveness → hostile `Ok(0)` → docs fail-closed table / gate-6 non-claim → External→Gateway→Strict before SOCKS | None | Clean (2/2) |

### Iterative-review-simplify (after adversarial clean)

Each cycle: Code Reuse → Code Efficiency → Code Quality and Bugs (+ simplify discipline).

| Cycle | Themes | Outcome |
|---|---|---|
| Sim-1 | Reuse: reject exporting configure `NONZERO_GATEWAY_METHODS` / sharing VNC helpers; Efficiency: pure helpers, no I/O; Quality: LOOPBACK_HOST already single source | Clean (1/3) |
| Sim-2 | Exhaustive never-SOCKS match sufficient vs bait wrapper; no hot-path alloc churn; docs table matches error variants | Clean (2/3) |
| Sim-3 | Diff hygiene in-scope; CredSSP/Connect untouched; no further validated churn | Clean (3/3) |

No simplify implementation edits → adversarial re-loop not required (counter remains 2/2 from Adv-1/Adv-2).

---

## Regression tests (`rdp::target::tests`)

- `loopback_host_matches_ipv4_localhost`
- `tunnel_present_is_local_forwarder_never_socks_variant`
- `direct_rejects_empty_host_and_zero_port_without_tunnel`
- `hostile_ok_zero_forwarder_port_fail_closed`
- `tunnel_path_binds_trimmed_host`
- `ipv6_and_bracketed_host_preserved_on_forwarder_path`
- `forwarder_bind_failed_display_is_non_secret`
- `prepare_external_before_socks_reject`
- `prepare_policy_gateway_before_bind` (nonzero incl. `3` / extremes)
- `prepare_socks_reject_source_is_none`
- Existing: Direct / Fake loopback / bind host / fail / zero port / validate-before-bind / trim / NUL / SOCKS reject / policy-before-bind / Debug

---

## Final verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-surface-win --features rdp
```

Result: **pass** — **135** unit tests with `--features rdp` (prior 126 + 9 new target regressions).  
`git diff --check` clean on in-scope paths. CredSSP wipe / Connect paths not modified.

## Remaining blockers

- Live `bind_local_forwarder` + OCX Connect stay deferred (selection stub + Fake only).
- Session orchestrator still fails closed on RDP before establish.
