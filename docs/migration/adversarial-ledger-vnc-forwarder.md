# Adversarial ledger — VNC `select_vnc_connect_target` / LocalForwarder stub

**Scope:** `rust/crates/wormhole-vnc/src/target.rs` (+ `error.rs` variants used by the stub), `docs/migration/09-vnc.md`  
**Authority:** adversarial-review-fix (edit in scope; no live RFB; no C# mutations)  
**Out of scope:** live `wormhole-tunnels` bind, `vnc-rs` TCP, GPUI blit, framebuffer/input (see `adversarial-ledger-vnc-framebuffer.md`)  
**Baseline (pre-fix):** `cargo test -p wormhole-vnc` **46** passed; `--features engine` **47** passed.

Attack focus:

- Tunnel on → `LocalForwarder` only (never SOCKS)
- Tunnel off → `Direct`
- Fail-closed on bind failure; host/port validation
- `FakeTunnelForwarder` records binds; no network
- Docs accurate

---

## Findings

| ID | Sev | Location | Issue | Evidence | Disposition |
|---|---|---|---|---|---|
| VNF-001 | P2 | `target.rs` tests | “Never SOCKS” under-pinned (trait omits SOCKS but no exhaustive LocalForwarder-only pin) | Attack: tunnel on → LocalForwarder only | **Fixed** — `tunnel_present_is_local_forwarder_never_socks_variant` |
| VNF-002 | P2 | `target.rs` tests | Direct-path empty/whitespace/zero-port only covered with tunnel present | `rejects_empty_*` used `Some(&fake)` only | **Fixed** — `direct_rejects_empty_host_and_zero_port_without_tunnel` |
| VNF-003 | P2 | `select_vnc_connect_target` | Defense-in-depth `local_port == 0` after bind untested | Hostile `Ok(0)` trait impl | **Fixed** — `OkZeroPortForwarder` + `hostile_ok_zero_forwarder_port_fail_closed` |
| VNF-004 | P3 | tests | Trim-on-tunnel-path / IPv6 host preservation unpinned | Only Direct trim; no IPv6/bracketed bind assert | **Fixed** — `tunnel_path_binds_trimmed_host`, `ipv6_and_bracketed_host_preserved_on_forwarder_path` |
| VNF-005 | P3 | `09-vnc.md` | Routing docs soft on fail-closed validation table | Attack: docs accurate + fail-closed | **Fixed** — fail-closed condition/error table + Fake notes |
| VNF-006 | P3 | `target.rs` | `LOOPBACK_HOST` vs `Ipv4Addr::LOCALHOST` could drift | Post-simplify delta | **Fixed** — `loopback_host_matches_ipv4_localhost` |
| VNF-007 | — | Public `LocalForwarder.connect_host` forgeable | Manual enum construction could set non-loopback | Speculative; `select_*` always sets loopback | **Rejected** — same as other pub structs; select is the API |
| VNF-008 | — | ZWSP-only / exotic Unicode host | Non-trimmable Unicode accepted | Speculative; C# same | **Rejected** — not in attack criteria |
| VNF-009 | — | Share `normalize_host` with `wormhole-session` | Duplicated helpers | Different error types / crates | **Rejected** — cross-crate churn out of scope |

---

## Fixes applied

- `target.rs`: `LOOPBACK_HOST` constant; stronger bind-failure match; regression tests for SOCKS-absence exhaustiveness, Direct boundaries, hostile `Ok(0)`, trim-on-bind, IPv6/bracketed hosts, Display non-secret, loopback pin
- `docs/migration/09-vnc.md`: fail-closed validation table for host/port/bind/local-port
- Ledger + README index entry

---

## Gate record

### Adversarial loop

| Cycle | Strategy | Accepted findings | Result |
|---|---|---|---|
| Adv-1 | Contract → boundary → state → concurrency → security → integration → perf → tests | VNF-001…004 | Fixed; reset |
| Adv-2 | Reverse: security → integration → docs → boundaries | VNF-005 | Fixed; reset |
| Adv-3 | Forward: C# parity + fail-closed + Fake no-network | None | Clean (1/2) |
| Adv-4 | Reverse: SOCKS absence, hostile ports, secrets in Display | None | Clean (2/2) |

### Iterative-review-simplify (after adversarial clean)

| Cycle | Reuse | Efficiency | Quality/Bugs | Accepted | Result |
|---|---|---|---|---|---|
| Sim-1 | `LOOPBACK_HOST`; drop dead SOCKS-bait field | Avoid redundant negative match | Stronger `ForwarderBindFailed` message assert | Yes → reset | Fixed |
| Adv-R* | Post-simplify delta | — | VNF-006 loopback drift pin | Fixed; adv reset → 2 clean | See below |
| Sim-2 | Helpers kept local (no session-crate share) | No I/O / no alloc churn | Tests aligned with docs table | None | Clean (1/3) |
| Sim-3 | Exhaustive match sufficient vs bait wrapper | Hot path N/A | Diff hygiene in-scope | None | Clean (2/3) |
| Sim-4 | Same | Same | No further validated churn | None | Clean (3/3) |

Post-simplify adversarial re-loop:

| Cycle | Strategy | Accepted | Result |
|---|---|---|---|
| Adv-R1 | Delta: `LOOPBACK_HOST`, exhaustive never-SOCKS test | VNF-006 | Fixed; reset |
| Adv-R2 | Security + fail-closed + docs table | None | Clean (1/2) |
| Adv-R3 | Boundary + Fake bind recording + C# loopback string | None | Clean (2/2) |

No further simplify edits after Adv-R2/R3 → Sim-2…4 remain the completed simplify gate.

---

## Regression tests (`target::tests`)

- `tunnel_present_is_local_forwarder_never_socks_variant`
- `direct_rejects_empty_host_and_zero_port_without_tunnel`
- `hostile_ok_zero_forwarder_port_fail_closed`
- `tunnel_path_binds_trimmed_host`
- `ipv6_and_bracketed_host_preserved_on_forwarder_path`
- `forwarder_bind_failed_display_is_non_secret`
- `loopback_host_matches_ipv4_localhost`
- Existing: Direct / Fake loopback / bind host / fail / zero port / validate-before-bind / trim / NUL / Debug

---

## Final verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-vnc
cargo test -p wormhole-vnc --features engine
```

Result: **pass** — default **53** tests; `--features engine` **54** tests. `git diff --check` clean on in-scope paths.

## Remaining blockers

- Live `bind_local_forwarder` + RFB dial still deferred (selection stub + Fake only).
- Context7 MCP unavailable in this environment; no crate pin change required for this stub.
