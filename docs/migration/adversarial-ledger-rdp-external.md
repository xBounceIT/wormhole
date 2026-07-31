# Adversarial ledger — RDP external mstsc / tunnel policy

Scope: `rust/crates/wormhole-surface-win/src/rdp/configure.rs` tunnel policy helpers
(`validate_tunnel_rdp_policy` / `TunnelRdpPolicy::use_external_client` /
`TunnelRdpConflict::ExternalClient` / `TUNNEL_EXTERNAL_CLIENT_UNSUPPORTED`) +
`prepare_rdp_connect_target` External-before-bind / External-before-SOCKS pins; docs in
`docs/migration/05-rdp-spike.md` + README ledger link  
Out of scope: CredSSP password wipe; OLE/overlay hosting; live `mstsc.exe` launch;
C# `ShouldUseExternalClientAsync` Azure-AD auto-detect (credential catalog / domain /
username signals — deferred; policy consumes the **effective** bool); C# sources
(read-only parity)  
Constraints / attack focus:
- `tunnel_enabled && use_external_client` → `Err(ExternalClient)` (host-network bypass)
- Tunnel off always allows external (C# only gates when `TunnelEnabled`)
- Priority External → Gateway → Strict (External wins even with gateway Direct/`0` + Require)
- Message identity with C# `TunnelExternalClientUnsupportedMessage`
- `prepare_rdp_connect_target` rejects External **before** Fake forwarder bind / SOCKS
- Pure policy (no hardware / gate-6 lab claim; no live mstsc)  
Baseline: `cargo test -p wormhole-surface-win --features rdp` green before review  
Design SoT: `docs/migration/05-rdp-spike.md`, AGENTS.md VPN routing notes, C#
`RdpSessionViewModel` connect guards (`ShouldUseExternalClientAsync` then fail closed)

## Findings

| ID | Sev | Location | Issue | Evidence | Disposition |
|---|---|---|---|---|---|
| EX-001 | P2 | `configure.rs` tests | External message only asserted via `contains("mstsc.exe")`, not C# literal | Editing Rust `TUNNEL_EXTERNAL_CLIENT_UNSUPPORTED` alone would still pass; attack requires identity with C# `TunnelExternalClientUnsupportedMessage` (parity with SA-001) | **Fixed** — `CSHARP_TUNNEL_EXTERNAL_CLIENT_UNSUPPORTED` + `external_client_message_matches_csharp_constant`; reject path asserts `to_string()` against C# text |
| EX-002 | — | Duplicate focused `validate_rdp_external_client_tunnel_combo` | Bool check is already the first arm of `validate_tunnel_rdp_policy` | Gateway combo helper exists for `!= 0` complexity; external is a single bool | **Rejected** — no extra helper; avoid duplicate sources |
| EX-003 | — | Wire AAD auto-detect into session / surface | C# `ShouldUseExternalClientAsync` also trips on AzureAD domain/username/credential | Policy correctly takes effective `use_external_client`; AAD resolution needs credential catalog + no live mstsc in unit tests | **Rejected** — deferred (out of scope); residual note |
| EX-004 | — | Depend `wormhole-session` on `wormhole-surface-win` | Would pull COM/OLE surface into session stubs | Gateway/strict residual: session intentionally has no surface-win dep | **Rejected** — keep deferred; do not duplicate policy in session |
| EX-005 | — | CredSSP / `WipePasswordOnDrop` | Out of scope | Untouched this review | **Rejected** — out of scope |
| EX-006 | — | Treat tunnel policy as gate-6 hardware | Attack: no hardware gate claim | Docs + unit tests only; no live mstsc | **Rejected** — invariant held |

## Fixes applied

- `rdp/configure.rs` — C# external-message pin const + identity test; strengthen
  `tunnel_rejects_external_client` (`message` / `Display` / `to_string` vs C# text)
- `docs/migration/05-rdp-spike.md` — External re-audit pin; effective-bool / AAD deferred note
- `docs/migration/README.md` — ledger link
- `docs/migration/adversarial-ledger-rdp-external.md` — this ledger

## Gate record

### Adversarial loop (this re-audit)

| Cycle | Strategy | Accepted findings | Result |
|---|---|---|---|
| Adv-0 | Contract → boundary → priority vs Gateway/Strict → message identity → prepare-before-bind → session dep → AAD deferred → no live mstsc | EX-001 | Fixed (test oracle only) |
| Adv-1 | Reverse: C# string byte-match; External-first pins already present; Fake bind count 0; no production policy change; no hardware claim | None | Clean (1/2) |
| Adv-2 | Tests-as-oracles → docs effective-bool wording → reject extra combo helper / session dep / AAD glue | None | Clean (2/2) |

### Iterative-review-simplify

| Cycle | Reuse | Efficiency | Quality/Bugs | Accepted | Result |
|---|---|---|---|---|---|
| Sim-1 | C# pin const shared by identity + reject tests (same pattern as Strict) | Pure helpers, no I/O | Reject inventing `validate_rdp_external_*` combo | None | Clean (1/3) |
| Sim-2 | Reject session duplicate of External reject | Unit tests only | Docs match host-network bypass + External→Gateway→Strict | None | Clean (2/3) |
| Sim-3 | No production policy edit beyond test pin | No hot-path work | prepare External-before-bind / SOCKS retained | None | Clean (3/3) |

No production simplify edits → adversarial re-loop not required beyond Adv-1/Adv-2 (counter 2/2).

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-surface-win --features rdp -- tunnel_rejects_external external_client_message external_checked prepare_policy_external prepare_external
```

Result: **pass** — focused external / priority / prepare pins green (incl. new
`external_client_message_matches_csharp_constant`).

## Residual notes

- C# `ShouldUseExternalClientAsync` Azure-AD auto-detect (node domain/username + credential
  catalog, fail-open to external on catalog error) remains deferred; callers must pass the
  **effective** `use_external_client` into `TunnelRdpPolicy`.
- Live `mstsc.exe` launch / crash-sentinel auto-flag remain deferred (no live mstsc in tests).
- Session-layer wiring stays deferred — no `wormhole-surface-win` dep from `wormhole-session`.
- CredSSP password wipe was intentionally not modified.

## Re-audit pin (2026-07-31)

**Verdict: already solid — test-oracle pin only; no production policy change.**

| Check | Status |
|---|---|
| `tunnel_enabled && use_external_client` → `Err(ExternalClient)` | Present + unit-covered |
| Tunnel off allows external (+ gateway/strict extremes) | Present + unit-covered |
| External → Gateway → Strict (incl. gateway Direct + Require) | Present + unit-covered |
| C# `TunnelExternalClientUnsupportedMessage` byte-match | **Pinned** (EX-001) |
| `prepare_rdp_connect_target` External before Fake bind / SOCKS | Present |
| Pure Rust / Fake; no live mstsc / OCX | Held |

**Parent: SKIP adversarial** — no intentional production behavior change; Adv 2/2 + Sim 3/3 stand.
