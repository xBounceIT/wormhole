# Adversarial ledger — SFTP `select_sftp_transport` SOCKS routing

**Scope:** `rust/crates/wormhole-sftp/src/transport.rs` (+ routing error surfaces in `error.rs`), `docs/migration/11-sftp.md`, README ledger link  
**Authority:** adversarial-review-fix (edit in scope; no C# mutations; no live SOCKS/russh dial)  
**Preserved:** Serialized ops / cancel gate, `public_message` Backend redaction, unsafe-name rejection  
**Baseline (pre-fix):** `cargo test -p wormhole-sftp` green; route table present, host-preservation / error-surface pins thin  
**Compared against:** C# `SftpService.ConnectAsync` (`Services/SftpService.cs`)

---

## Accepted findings and fixes

| ID | Sev | Location | Invariant / evidence | Fix | Verification |
|---|---|---|---|---|---|
| SOCKS-01 | P2 | `transport.rs` rustdoc / `11-sftp.md` | Attack “host preserved” under-documented vs C# `ConnectionInfo(profile.Host,…, ProxyTypes.Socks5,…)`; `FakeTunnelSocks::loopback` naming risked implying a bind | Document route-only enum; Fake is pure data / no bind; doc + ledger link | docs + `socks5_keeps_ssh_connect_host_at_call_site` |
| SOCKS-02 | P2 | `transport.rs` tests | `InvalidSocksPort` Display/`public_message`/Debug and IPv6 `:0` not pinned; fail-closed vs Direct unstated in tests | Extend `zero_port_socks_rejected`; pin messaging | that test |
| SOCKS-03 | P2 | `transport.rs` tests | Routing errors / Fake “no network” / secret-free surfaces not machine-checked against attack list | `routing_errors_omit_secrets`, `fake_tunnel_socks_is_pure_data`; Default → `TunnelSocksRequired` | those tests |
| SOCKS-04 | P3 | README / ledger | Missing `adversarial-ledger-sftp-socks.md` + README row | Add ledger + README + `11-sftp.md` link | docs review |
| SOCKS-05 | P3 | `socks5_keeps_ssh_connect_host_at_call_site` | Tautological local `assert_eq` on unchanged locals gave false confidence for “host preserved” | Pin proxy-only `SftpTransport::Socks5` (addr equality + port ≠ 22); drop vacuous asserts | that test |

### Simplify delta (post-adversarial)

| ID | Sev | Location | Change | Verification |
|---|---|---|---|---|
| S-01 | — | `transport.rs` tests | Drop redundant `matches!(Socks5)` after `socks5().expect`; drop accessor-only trailing assert and duplicate ip/port checks covered by `assert_eq!(ep.addr, proxy)` | `cargo test -p wormhole-sftp --lib transport::` |

---

## Rejected candidates

| Candidate | Reason |
|---|---|
| Make `Socks5Endpoint::new` return `Result` (reject port 0) | Matches HTTP `Socks5Proxy::new` + tunnels infallible `new`; `select` / `loopback` are the choke points |
| Add `plan_sftp_dial(host, port, tunnel)` bundling host | Route-only API is intentional; host stays at call site (documented + tested) |
| Depend on `wormhole-tunnels` for shared `Socks5Endpoint` | Explicit isolation for unit tests / no tunnels dep |
| `Send + Sync` on `TunnelSocksSource` | Sync select only; production adapter lands with session wiring |
| Live SOCKS CONNECT / russh channel | Documented non-goal; deferred with `06-ssh-spike.md` |
| Soften fail-closed to Direct when SOCKS missing | Would violate C# / SSH terminal leak-prevention |
| Remove `FakeTunnelSocks::none` in favor of `Default` only | Named constructor is clearer at call sites |
| Collapse dual port-0 checks (`loopback` + `select`) | Defense in depth; matches HTTP builder pattern |

---

## Adversarial clean passes (2 required)

Reset after each fix batch. Test-only simplify (S-01) did not require adversarial re-loop (no production code delta).

### Clean pass 1 — order: security → contract → boundaries → test resistance → integration

- Routing errors omit password/secret/`hunter2` on Display/Debug/`public_message`; endpoint has no auth fields.
- No tunnel → Direct; tunnel+SOCKS → Socks5 (proxy-only); tunnel sans SOCKS → `TunnelSocksRequired` (not Direct); port 0 → `InvalidSocksPort`.
- IPv4/IPv6 `:0`, non-loopback proxy addr preserved; Default fake fails closed.
- Docs / C# `SftpService` / tunnels shape (`addr` only) aligned; no tunnels crate dep.
- **Accepted findings:** none.

### Clean pass 2 — order: integration → boundaries → concurrency → operability → security → contract → tests

- README + `11-sftp.md` ledger link; exports in `lib.rs` match module surface.
- Port 0 / missing SOCKS never silent-Direct; Fake constructs without sockets.
- `select_sftp_transport` is pure sync (no shared mutable state).
- Error messages stable and credential-free.
- Host preservation is structural (no target-host field on `SftpTransport::Socks5`).
- **Accepted findings:** none.

`adversarial_clean_passes = 2`.

---

## Iterative-review-simplify (3 clean cycles)

Each cycle: Code Reuse → Code Efficiency → Code Quality and Bugs (+ simplify discipline).

| Cycle | Themes | Outcome |
|---|---|---|
| 1 (fix) | Reuse (keep dual port-0 / named `none`); quality (redundant test asserts) | S-01 applied → counter reset |
| 1 (clean) | Reuse (`loopback` composition); efficiency (Copy endpoint); quality (match table clarity) | Clean |
| 2 | Reject `plan_sftp_dial` / tunnels merge; keep fail-closed table; Fake pure-data test retained | Clean |
| 3 | Docs/`11-sftp.md` parity; no further validated churn | Clean |

`simplify_clean_passes = 3`.

---

## Regression tests added/updated

- `socks5_keeps_ssh_connect_host_at_call_site` — proxy-only Socks5 route (no rewritten SSH target field)
- `zero_port_socks_rejected` — Display/`public_message`/Debug + IPv6 `:0`
- `routing_errors_omit_secrets` — TunnelSocksRequired + InvalidSocksPort surfaces
- `fake_tunnel_socks_is_pure_data` — in-memory construction / Default = none
- `tunnel_without_socks_fails_closed` — Debug + Default fail-closed

---

## Final verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-sftp
```

Results: lib transport + error/path/queue units green; `serialize_queue` 12 passed; doc-tests 0.
