# Adversarial ledger — HTTP SOCKS vs local-forwarder selection

**Scope:** `rust/crates/wormhole-http/src/route.rs` (`select_http_tunnel_route`,
`HttpTunnelRoute`, `FakeHttpTunnelRoute`), builders/cert preservation call sites,
`wormhole-session` `connect_http` wiring, `docs/migration/10-http.md`  
**Out of scope:** WebView2 env create, live BindLocalForwarder I/O, Bitwarden profiles  
**Authority:** full adversarial-review-fix (edit in scope)  
**Baseline:** `cargo test -p wormhole-http` — 40 green; `orchestrator_fakes` 31 green  
**Final:** `wormhole-http` **40** green; `orchestrator_fakes` **32** green  

Compared against C#: `HttpSessionViewModel.BuildTargetAsync` hybrid
(prefer `Socks5Endpoint`, else `BindLocalForwarderAsync`). Serial never tunnels.

Attack focus: SOCKS prefer then LocalForwarder; Direct without lease; port 0 reject;
cert policy preserved; Serial never uses HTTP route.

Context7 MCP unavailable in this environment.

---

## Gate summary

| Gate | Result |
|---|---|
| Adversarial clean passes | **2** consecutive (post-fix + post-simplify re-run) |
| Iterative-review-simplify clean passes | **3** consecutive |
| `cargo test -p wormhole-http` | **pass** (40) |
| `cargo test -p wormhole-session --test orchestrator_fakes` | **pass** (32) |
| `git diff --check` (scoped) | **pass** |

---

## Accepted findings

### HTROUTE-01 — No pure selector for SOCKS-prefer / forwarder-fallback (`P2`) — **fixed**

- **Where:** selection lived only inline in `SessionOrchestrator::connect_http`
- **Invariant:** Prefer SOCKS when present; else local forwarder; Direct when no lease
- **Evidence:** Builders existed; preference itself untested in `wormhole-http`
- **Impact:** Regressions could silently invert SOCKS vs loopback (SNI/cert breakage)
- **Fix:** `select_http_tunnel_route` + `HttpTunnelRoute::{Direct,Socks5,LocalForwarder}` + `FakeHttpTunnelRoute`
- **Regression:** `prefer_socks5_when_endpoint_present`, `else_local_forwarder_when_no_socks`, `no_tunnel_selects_direct`, `socks_presence_never_selects_forwarder`, `zero_port_socks_rejected`

### HTROUTE-02 — Cert policy not pinned through selection→builder composition (`P3`) — **fixed**

- **Where:** existing builder matrix did not exercise `select_http_tunnel_route`
- **Invariant:** scheme × leaf flag preserved across Direct / SOCKS / forwarder after selection
- **Fix:** `selection_then_builder_preserves_cert_policy`
- **Regression:** same test

### HTROUTE-03 — Serial scope under-documented / weakly pinned (`P3`) — **fixed**

- **Where:** docs + tests
- **Invariant:** Serial never uses HTTP tunnel hybrid routing
- **Evidence:** orchestrator already skips tunnel for Serial; http crate had no note
- **Fix:** rustdoc + `10-http.md` selection table; `serial_never_applies_http_tunnel_routing` exhaustive `HttpScheme` match
- **Regression:** that test + existing `serial_ignores_tunnel_enabled` in session

### HTROUTE-04 — Orchestrator double-match left unreachable LocalForwarder-without-lease (`P3`) — **fixed**

- **Where:** first `connect_http` wiring matched route then re-unwrapped `lease`
- **Invariant:** LocalForwarder only when lease is `Some`
- **Fix:** lease-first match; SOCKS/forwarder only under `Some(lease)`; Direct arm fail-closed if selector drifts
- **Regression:** `https_via_tunnel_socks`, `https_via_tunnel_forwarder_when_no_socks`, `http_direct_target`

### HTROUTE-05 — Session SOCKS / Direct paths under-asserted vs attack checklist (`P3`) — **fixed**

- **Where:** `orchestrator_fakes` `https_via_tunnel_socks`, `http_direct_target`
- **Invariant:** Prefer-SOCKS preserves HTTPS ignore-cert; Direct has no proxy / no original / no lease
- **Evidence:** Forwarder test asserted `ignore_cert_errors`; SOCKS/Direct did not pin cert / Direct fields
- **Impact:** Session wiring could drop cert policy or leave proxy residue without failing CI
- **Fix:** Assert cert + `original_uri` on SOCKS; assert Direct field set (no socks / no original / no tunnel id / no ignore on plain HTTP)
- **Regression:** strengthened `https_via_tunnel_socks`, `http_direct_target`

### HTROUTE-06 — Port-0 SOCKS boundary under-pinned (IPv6 + `loopback(0)`) (`P3`) — **fixed**

- **Where:** `route::tests::zero_port_socks_rejected`
- **Invariant:** Port 0 → `InvalidPort` for IPv4 and IPv6; never Direct / never LocalForwarder
- **Evidence:** Only IPv4 `with_socks5(:0)` covered; SFTP parity includes IPv6 `:0` + `loopback(0)` Err
- **Fix:** Assert `FakeHttpTunnelRoute::loopback(0)` / `Socks5Proxy::loopback(0)` Err + IPv6 `:0`
- **Regression:** `zero_port_socks_rejected`

### HTROUTE-07 — Session wiring lacked port-0 SOCKS fail-closed path (`P2`) — **fixed**

- **Where:** `connect_http` via `LeaseHttpTunnelRoute` → `select_http_tunnel_route`
- **Invariant:** Lease with SOCKS port 0 → Failed `Http(InvalidPort(0))`; no Connected Http; lease released; no BindLocalForwarder fallback
- **Evidence:** Unit selector pinned port 0; orchestrator adapter uses `Socks5Proxy::new` without port check (relies on selector); no integration test
- **Impact:** Adapter/selector drift could fall through to Direct/forwarder or leave a leaked lease
- **Fix:** `ZeroPortSocksBroker` + `https_via_tunnel_zero_port_socks_rejected`
- **Regression:** that test

---

## Rejected candidates

| ID | Severity | Reason |
|---|---|---|
| REJ-01 | — | Pull `ProtocolType` into `wormhole-http` to forbid Serial — wrong layer; Serial skip stays in orchestrator |
| REJ-02 | — | Force Direct path through `select_http_tunnel_route(None)` — redundant; unit tests pin `None → Direct`; lease-first match is clearer for LocalForwarder |
| REJ-03 | — | Depend on `wormhole-tunnels` for `Socks5Endpoint` — keep local `Socks5Proxy` + trait adapter (same as SFTP) |
| REJ-04 | — | Fail closed without SOCKS (SFTP-style) — would break C# HTTP hybrid / WireGuard shapes |
| REJ-05 | — | Share ForwarderOnly/ZeroPort broker boilerplate — test clarity beats one-off abstraction |
| REJ-06 | — | Assert FakeTunnelProvider bind-count on SOCKS prefer — route=`Socks5` already pins prefer; bind counter not on FakeTunnelBroker |

---

## Gate record

### Adversarial loop

| Cycle | Strategy | Accepted findings | Result |
|---|---|---|---|
| Adv-1 | Contract → boundary → state → concurrency → security → integration → perf → tests | HTROUTE-01…04 (prior) + HTROUTE-05…07 (this pass) | Fixed; reset |
| Adv-2 | Reverse: Serial leakage → SOCKS port 0 → cert matrix → orchestrator arms | None | Clean (1/2) |
| Adv-3 | C# hybrid oracle → SFTP contrast → session fakes resistance | None | Clean (2/2) |

### Iterative-review-simplify (after adversarial clean)

| Cycle | Reuse | Efficiency | Quality/Bugs | Accepted | Result |
|---|---|---|---|---|---|
| Sim-1 | Align error variant with SOCKS semantics | N/A | `TunnelError::Socks5` in zero-port stub bind | Yes → reset | Fixed |
| Sim-2 | Docs list session wiring tests | No extra I/O | `10-http.md` Verification includes `orchestrator_fakes` | Yes → reset | Fixed |
| Sim-3 | Lease adapter stays private; no over-share of test brokers | Selection remains pure | Attack checklist covered | None | Clean (1/3) |
| Sim-4 | Same | Same | Direct fail-closed arm kept (exhaustive) | None | Clean (2/3) |
| Sim-5 | Same | Same | Diff hygiene in-scope | None | Clean (3/3) |

Simplify changed tests/docs → adversarial re-run on delta:

| Cycle | Strategy | Accepted | Result |
|---|---|---|---|
| Adv-R1 | Delta: zero-port session wiring, cert asserts, docs verification | None | Clean (1/2) |
| Adv-R2 | Reverse: SOCKS prefer / Serial / cert / port-0 fail-closed + lease release | None | Clean (2/2) |

---

## Invariants pinned

| Invariant | Status |
|---|---|
| No lease → Direct | **Pinned** (unit + `http_direct_target`) |
| Lease + SOCKS (port ≠ 0) → Socks5 (never forwarder) | **Pinned** |
| Lease + no SOCKS → LocalForwarder | **Pinned** |
| SOCKS port 0 → `InvalidPort` (IPv4/IPv6; session wiring) | **Pinned** |
| Cert policy preserved selection→builder + session SOCKS | **Pinned** |
| Serial never applies HTTP hybrid selector | **Pinned** (docs + scheme exhaustiveness; session skip) |
| HTTP falls back (unlike SFTP fail-closed) | **Pinned** (docs + tests) |

---

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-http
cargo test -p wormhole-session --test orchestrator_fakes
```

Result: **pass** — 40 (`wormhole-http`) + 32 (`orchestrator_fakes`).

Attack-focus checklist:

| Focus | Status |
|---|---|
| SOCKS prefer then LocalForwarder | **Pinned** |
| Direct without lease | **Pinned** |
| Port 0 reject | **Pinned** (unit + session) |
| Cert policy preserved | **Pinned** |
| Serial never uses HTTP route | **Pinned** |
