# Adversarial ledger — SSH SOCKS5 tunnel route select glue

**Scope:** `rust/crates/wormhole-ssh/src/tunnel_route.rs` (`select_ssh_connect_target` /
`select_ssh_tunnel_route` / `SshConnectTarget` / `FakeTunnelSocks` / `TunnelSocksSource` /
`to_transport`), exports in `lib.rs`, SOCKS route sections of `docs/migration/06-ssh-spike.md` +
`07-tunnels-mcp.md`, README / feature-matrix ledger links  
**Out of scope:** Live SOCKS5 CONNECT handshake (`Socks5NotImplemented`); session orchestrator
auto-wiring (Pending); C# mutations; `wormhole-tunnels` / `wormhole-sftp` crates  
**Date:** 2026-07-31  
**Authority:** full adversarial-review-fix (edit in scope; no commit/push)  
**Gates:** 2 clean adversarial cycles + 3 clean iterative-review-simplify cycles (adversarial
renewed after fix batches)

Compared against C#: `SshSessionService.ConnectAsync` fail-closed when tunnel lease lacks SOCKS5
(no silent public dial); Serial never tunnels.

Context7 MCP unavailable in this environment.

---

## Gate summary

| Gate | Result |
|---|---|
| Adversarial clean passes | **2** consecutive (post-fix) |
| Iterative-review-simplify clean passes | **3** consecutive |
| `cargo test -p wormhole-ssh tunnel_route` | **pass** (13 with `client`; 12 `--no-default-features`) |
| `git diff --check` (scoped) | **pass** |

---

## Baseline

- Glue already present at `tunnel_route.rs` (always-on; `to_transport` behind `client`).
- Pre-fix focused: 11–12 unit tests green; README/feature-matrix/`06`/`07` linked
  `adversarial-ledger-ssh-tunnel-route.md` which **did not exist**.
- User-required ledger slug: `adversarial-ledger-ssh-socks-route.md`.

---

## Accepted findings and fixes

| ID | Sev | Location | Invariant / evidence | Fix | Verification |
|---|---|---|---|---|---|
| SSH-SOCKS-01 | P2 | README / `06-ssh-spike.md` / `07-tunnels-mcp.md` / feature-matrix | Ledger file missing; index claimed “review closed” for non-existent `…-ssh-tunnel-route.md` | Create `adversarial-ledger-ssh-socks-route.md`; retarget all links to that slug | docs + this ledger |
| SSH-SOCKS-02 | P3 | `tunnel_route.rs` tests | IPv6 non-zero SOCKS select + `to_transport` host mapping unpinned (only `:0` / IPv4 covered) | `ipv6_nonzero_socks_preserved`; extend `to_transport_maps_direct_and_socks` for `::1` | those tests |
| SSH-SOCKS-03 | P3 | module rustdoc / `06-ssh-spike.md` | Oracle named `SshSessionViewModel` / “SSH terminal” — fail-closed throw lives in `SshSessionService` | Cite `SshSessionService` / `SftpService` | docs review |

### Simplify delta (post-adversarial)

| ID | Sev | Location | Change | Verification |
|---|---|---|---|---|
| S-01 | — | `connect_target_is_direct_or_socks5_only` | Clarify exhaustive-match comment (LocalForwarder compile pin) | `cargo test -p wormhole-ssh tunnel_route` |

No production-logic simplify churn after S-01 (comment-only); adversarial re-loop still completed on the full scope.

---

## Rejected candidates

| Candidate | Reason |
|---|---|
| Soften fail-closed → Direct when SOCKS missing | Would leak SSH bytes off-tunnel (violates C# `SshSessionService`) |
| Add LocalForwarder fallback (HTTP hybrid) | SSH/SFTP are stream SOCKS-only; intentional contrast with HTTP |
| Depend on `wormhole-tunnels` for shared endpoint | Keep Fake isolation; `addr`-only local type matches SFTP |
| `Socks5Endpoint::new` / `TunnelSocksEndpoint::new` reject port 0 | Matches SFTP/HTTP: `loopback` + `select` are choke points |
| `Send + Sync` on `TunnelSocksSource` | Sync select only; production adapter lands with session wiring |
| Bundle host into `plan_ssh_dial` | Route-only API; CONNECT host stays at call site |
| Change `public_message` to owned `String` for interpolated port | Only port `0` is emitted; `&'static str` matches other SSH glue errors |
| Live SOCKS CONNECT / orch wiring | Documented non-goal / Pending |
| Collapse dual port-0 checks (`loopback` + `select`) | Defense in depth; SFTP/HTTP pattern |
| Share Fake with `wormhole-sftp` | Cross-crate dep for identical stubs adds coupling without payoff |

---

## Adversarial clean passes (2 required)

Reset after each fix batch. Final pair below is post SSH-SOCKS-01…03 + S-01.

### Clean pass 1 — order: security → contract → boundaries → concurrency → integration → tests

- Routing errors omit password/secret/`hunter2` on Display/Debug/`public_message`; route endpoint has no auth fields; `to_transport` clears dialer creds.
- Serial → always Direct; SSH + tunnel off → Direct (even if SOCKS present); SSH + tunnel on + SOCKS → Socks5 (proxy-only); missing SOCKS / port 0 → fail closed (never Direct / never LocalForwarder).
- IPv4/IPv6 `:0` rejected; IPv6 non-zero addr preserved; Fake constructs without sockets.
- Pure sync select (no shared mutable state).
- Docs / C# `SshSessionService` / SFTP shape aligned; ledger slug present.
- **Accepted findings:** none.

### Clean pass 2 — order: integration → C# oracle → Serial leakage → HTTP contrast → operability → security → contract → tests

- README + `06`/`07`/feature-matrix link `adversarial-ledger-ssh-socks-route.md`; `lib.rs` exports match module surface; always-on under `--no-default-features` (`to_transport` gated).
- C# throw-when-tunnel-sans-SOCKS mirrored by `TunnelSocksRequired` when `tunnel_enabled`.
- Serial + tunnel on + no SOCKS must not Err (never consults SOCKS).
- Exhaustive `SshConnectTarget` match pins no LocalForwarder arm.
- Error messages stable and credential-free; host preservation structural (no SSH target field on `Socks5`).
- **Accepted findings:** none.

`adversarial_clean_passes = 2`.

---

## Iterative-review-simplify (3 clean cycles)

Each cycle: Code Reuse → Code Efficiency → Code Quality and Bugs (+ simplify discipline).

| Cycle | Themes | Outcome |
|---|---|---|
| 1 (fix) | Quality: exhaustive-match comment clarity | S-01 → counter reset |
| 1 (clean) | Reuse (`loopback` composition; keep dual port-0 / named `none`); efficiency (Copy endpoint); quality (oracle naming already fixed) | Clean |
| 2 | Reject tunnels merge / `plan_ssh_dial` / soft Direct; keep fail-closed table; Fake pure-data retained | Clean |
| 3 | Docs/`06`/`07`/README parity; no further validated churn | Clean |

`simplify_clean_passes = 3`.

---

## Invariants pinned

| Invariant | Status |
|---|---|
| `tunnel_enabled=false` → Direct (SOCKS ignored) | **Pinned** |
| `tunnel_enabled=true` + SOCKS (port ≠ 0) → Socks5 (proxy-only) | **Pinned** |
| `tunnel_enabled=true` + missing SOCKS / `None` → `TunnelSocksRequired` | **Pinned** |
| SOCKS port 0 → `InvalidSocksPort` (IPv4/IPv6; `loopback(0)`) | **Pinned** |
| Serial always Direct (never fail-closed on missing SOCKS) | **Pinned** |
| No LocalForwarder arm on `SshConnectTarget` | **Pinned** (exhaustive match) |
| IPv6 non-zero preserved; `to_transport` maps `::1` without dialer creds | **Pinned** |
| Errors secret-free | **Pinned** |
| Fake is pure data (no bind / no network) | **Pinned** |

---

## Regression tests added/updated

- `ipv6_nonzero_socks_preserved` — IPv6 loopback `:1080` → Socks5 with same addr
- `to_transport_maps_direct_and_socks` — also maps `::1:9050` with `username`/`password` None
- `connect_target_is_direct_or_socks5_only` — exhaustive Direct|Socks5 compile pin (comment)

---

## Final verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-ssh tunnel_route
cargo test -p wormhole-ssh --no-default-features tunnel_route
```

**Result (final):** default features — **13** tunnel_route passed; `--no-default-features` — **12** passed (`to_transport` test gated). No accepted non-blocked findings remain.
