# Adversarial ledger — Live physical-path client + WatchGuard establish glue

**Scope:** `rust/crates/wormhole-tunnels/src/os_adapters.rs` (new: `WindowsAdapterSource` + `Win32AdapterSource` + `FakeAdapterSource` + `Win32PhysicalNetworkPathProbe`), `src/providers/watchguard/portal.rs` (new), `src/providers/watchguard/mod.rs`, `src/providers/watchguard/establish.rs` (pub(crate) visibility only), `src/lib.rs`. `wormhole-tunnels/Cargo.toml` windows dep (Ndis/WinSock) was added by the interrupted implementer run and kept.

**Out of scope:** real socket connect (`ConnectTcpAsync` — host responsibility); live portal HTTP/OpenVPN; Stormshield portal (separate closed ledger); `FakePhysicalNetworkPath` (untouched, still default).

**Compared against:** C# `Services/Tunneling/WindowsPhysicalNetworkPathService.cs` (`GetAdaptersAddresses`/`GetBestInterfaceEx`, adapter id/name/is-active/indexes, `IsVpnLikeAdapter` incl. Tunnel/Ppp exclusion) and `Services/Tunneling/Watchguard/*`; Stormshield `portal.rs` as the mirror pattern.

**Authority:** full adversarial-review-fix (reviewer subagent; parent re-verified)  
**Baseline:** wormhole-tunnels lib **452** tests  
**Final:** wormhole-tunnels lib **457** tests

**Attack focus:** Win32 struct sizing/status matrix (`NO_ERROR` vs `ERROR_BUFFER_OVERFLOW` vs access-denied → fail-closed `Err`), unbounded adapter-table allocation (OOM → `AdapterBufferTooLarge` cap), OTP reuse backward-clock skew (fail-open bug fixed), no-usable-remote stuck cache entry, Tunnel/Ppp-kind owner exclusion in classification, Fake route-key normalization drift, secret leakage (OTP/password/token).

---

## Gate summary

| Gate | Result |
|---|---|
| Adversarial clean passes | **2** consecutive (+ 2 re-runs on IRS delta) |
| Iterative-review-simplify clean passes | **3** consecutive |
| `cargo test -p wormhole-tunnels --lib` | **pass** (457) |
| `cargo check --lib` / `--no-default-features` | **pass** (2 pre-existing entra warnings) |
| `git diff --check` (scoped) | **pass** |

---

## Accepted findings and fixes

| ID | Sev | Finding | Fix |
|---|---|---|---|
| F1 | P2 | `WatchguardOtpReuseGuard::check` fail-open on backward clock jump (negative elapsed → reuse accepted) | `to_std()` failure = inside-window (fail-closed); `otp_reuse_guard_rejects_on_backward_clock_skew` |
| F2 | P3 | `enumerate_adapters` sizing pass returned `Ok(empty)` on ANY non-NO_ERROR status (e.g. access denied) | Pure `sizing_pass()` — only NO_ERROR / BUFFER_OVERFLOW+zero → empty; other statuses → `Err` |
| F3 | P3 | Unbounded adapter-table allocation from OS sizing value → OOM abort | `MAX_ADAPTER_BUFFER_BYTES` (16 MiB) cap → `AdapterBufferTooLarge` |
| F4 | P3 | No-usable-remote profile left a garbage cache entry → stuck 30 days | `establish_watchguard_automatic` drops cache best-effort (cached and fresh); tests assert deletion |
| F5 | P3 | `classify_unknown_with_best_route` didn't exclude Tunnel/Ppp adapters (C# `IsVpnLikeAdapter` excludes unconditionally) | Kind gate added; 2 tests |
| Q1 | P3 | `FakeAdapterSource` route-key normalization inconsistent (script vs lookup) | Aligned trim+lowercase; case-insensitivity test |

### Rejected candidates

`is_vpn_like_adapter` lacks the "wireguard" marker vs C# (pre-existing read-only); real probe classifies hostname-only portals as `Unknown` → fail-closed (documented Lab limitation, shared with Stormshield).

---

## Test command

```powershell
cd rust
cargo test -p wormhole-tunnels --lib
cargo check -p wormhole-tunnels --lib --no-default-features
```

**Counts:** `os_adapters` **22**, watchguard portal **77**; full tunnels lib **457**.