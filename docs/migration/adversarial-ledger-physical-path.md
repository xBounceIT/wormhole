# Adversarial ledger — physical network path / split-routing Fake glue

**Scope:** `rust/crates/wormhole-tunnels/src/physical_network_path.rs`
(`PhysicalNetworkRoute` / `PhysicalNetworkPath` / `PhysicalNetworkPathProbe` /
`FakePhysicalNetworkPath` / `classify_split_route` / `is_vpn_like_adapter` /
`build_physical_network_path`), exports in `lib.rs`, `TunnelError::InvalidHost`,
`Cargo.toml` description, docs `07-tunnels-mcp.md` / `feature-matrix.md` /
README ledger link; this ledger.

**Out of scope:** Live `dnsapi` / `iphlpapi` P/Invoke; per-interface `DnsQueryEx`;
`ConnectTcpAsync` socket racing; Stormshield portal / establish wiring to supply
`transport_adapter_ids`; GPUI.

**Compared against:** C# `WindowsPhysicalNetworkPathService` /
`IWindowsPhysicalNetworkPathService` / `WindowsPhysicalNetworkPath` /
`IsVpnLikeAdapter` preflight (adapter ordering, VPN exclusion, no destination DNS
during `GetBestPathAsync`, fail-closed when no active physical interface).

**Authority:** full adversarial-review-fix (edit in scope; no child agents;
no commit/push)  
**Baseline (pre-fix):** new glue module + unit tests  
**Final:** `cargo test -p wormhole-tunnels --lib` green (**367** unit incl. **15**
`physical_network_path`).

Context7 MCP unavailable in this environment (no dependency pin changes).

---

## Gate summary

| Gate | Result |
|---|---|
| Adversarial clean passes | **2** consecutive (independent attack order; re-established after fix + simplify delta) |
| Iterative-review-simplify clean passes | **3** consecutive |
| `cargo test -p wormhole-tunnels --lib` | **pass** (367) |
| `git diff --check` (scoped) | **pass** |

---

## Attack criteria (user)

| Criterion | Result |
|---|---|
| Direct / Physical / Unknown classification | **Held** — `PhysicalNetworkRoute` + `classify_split_route` |
| Fake interface (no live Win32 DNS/route APIs) | **Held** — `FakePhysicalNetworkPath` + in-memory adapters |
| Unit-testable | **Held** — **15** module tests |
| Fail-closed on empty host | **Held** — `TunnelError::InvalidHost` |
| Prefer `wormhole-tunnels`; no GPUI | **Held** |

---

## Accepted findings and fixes

| ID | Sev | Location | Invariant / evidence | Fix | Verification |
|---|---|---|---|---|---|
| PNP-01 | P2 | `classify_split_route` | Link-local literals must not classify as `Physical` | `is_loopback_host` includes link-local | `classify_link_local_is_direct` |
| PNP-02 | P2 | `FakePhysicalNetworkPath` | Host override map must be case-insensitive | `to_ascii_lowercase` on insert + lookup | `fake_host_override_is_case_insensitive` |
| PNP-03 | P2 | `build_physical_network_path` | Unknown `PhysicalAdapterKind::Other` must not enter path (C# rejects unknown types) | Score `0` filter | `get_best_path_rejects_unknown_interface_types` |
| PNP-04 | P3 | `FakePhysicalNetworkPath` Debug | Host override keys must not appear in Debug | Count-only Debug struct | `fake_debug_omits_host_overrides` |
| PNP-05 | P3 | docs | Physical path still Pending in matrix/README | Doc bullets + matrix row + ledger + README row | doc review |

### Simplify delta (post-adversarial)

| ID | Sev | Location | Change | Verification |
|---|---|---|---|---|
| S-01 | — | `with_host_route` / `with_default_route` | Remove unnecessary `mut self` | compile |
| S-02 | — | `adapter_ids` | Explicit `&String` closure type (compile fix) | compile |
| S-03 | — | tests | NBSP-only host fail-closed regression | `nbsp_only_host_fail_closed` |

Production deltas from PNP-01…PNP-03 → adversarial re-looped to 2 clean.

---

## Rejected candidates

| Candidate | Reason |
|---|---|
| Live `DnsQueryEx` / `GetBestInterfaceEx` in Rust | Explicit non-goal — Fake glue only |
| Classify public DNS names as `Physical` without probes | Would guess VPN capture behavior; `Unknown` is conservative |
| Put glue in `wormhole-diagnostics` | Tunnel transport pinning belongs with `wormhole-tunnels` / Stormshield sidecar JSON |
| `ConnectTcpAsync` Fake stream racing | Out of scope — classification + adapter preflight only |
| Wire Stormshield establish to call `get_best_path` | Establish/portal paths remain Pending; Fake supplies `transport_adapter_ids` in tests |
| Map empty host to `Unknown` instead of `Err` | User rule + C# rejects unusable targets fail-closed |
| GPUI / WinUI surface | Explicit non-goal |

---

## Adversarial clean passes (2 required)

### Clean pass 1 — order: contract → boundary → state → security → integration

- `PhysicalNetworkRoute` variants match user contract; public hosts → `Unknown`.
- Empty / whitespace / NBSP-only host → `InvalidHost`; loopback + link-local → `Direct`; RFC1918 + `.local` → `Physical`.
- `get_best_path` does not resolve destination DNS; VPN-like adapters excluded; inactive physical adapters retained for recovery parity.
- `FakePhysicalNetworkPath` Debug omits override host strings.
- Matrix / 07 / README link ledger; exports match module surface.

### Clean pass 2 — order: security → C# oracle → concurrency → boundary → contract

- No secrets in Debug; adapter names only in struct Debug (lab parity with C# tests).
- C# `GetBestPath_ExcludesVpnAndKeepsStablePhysicalFallbacks` mirrored by Fake adapter script test.
- Mutex-backed Fake: poison → `Establish` err (tests single-threaded).
- Override case folding + blank adapter id unavailable pinned.
- **Accepted findings:** none.

---

## Iterative-review-simplify clean passes (3 required)

1. Post-PNP fixes: link-local Direct, case-insensitive overrides, unknown kind filter.
2. S-01 / S-02 / S-03 compile + test hygiene — suite green.
3. Doc-only delta (ledger / matrix / 07) — no code change; third clean simplify.

---

## Test command

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-tunnels physical_network_path
cargo test -p wormhole-tunnels --lib
```

**Counts:** `physical_network_path` module **15** unit tests; full tunnels lib **367**.
