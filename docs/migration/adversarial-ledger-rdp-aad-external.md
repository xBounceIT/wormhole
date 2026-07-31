# Adversarial ledger — RDP Azure AD / external-client Fake detection glue

Scope: `rust/crates/wormhole-surface-win/src/rdp/aad_external_client_glue.rs` (+ `rdp/mod.rs`
exports, `Cargo.toml` optional `uuid` for scripted catalog ids), docs in
`docs/migration/05-rdp-spike.md` AAD section + README link + `feature-matrix.md`  
Out of scope: live WAM/AAD; `Process::Command` / `mstsc.exe` spawn; CredSSP / display /
performance Fake rewrites; `wormhole-session` surface-win dependency; live SQLite credential
catalog  
Constraints / attack focus:
- C# `AzureAdCredentialDetector` domain/prefix heuristics (no bare onmicrosoft UPN)
- C# `ShouldUseExternalClientAsync` order: opt-in → node domain → node username → catalog
- Catalog lookup error → fail-safe external (embedded mstscax crash path)
- Non-`Rdp` credential protocol → embedded
- Node signals short-circuit before catalog lookup
- Compose with `RdpExternalMstscGlue` only when `PreferExternalMstsc`
- Embedded path skips external tunnel evaluate
- No secrets in Debug  
Baseline: `cargo test -p wormhole-surface-win --features rdp -- aad_external` green before review  
Design SoT: `docs/migration/05-rdp-spike.md`, C# `Helpers/AzureAdCredentialDetector.cs`,
`RdpSessionViewModel.ShouldUseExternalClientAsync`; tunnel parent
[adversarial-ledger-rdp-external-mstsc.md](adversarial-ledger-rdp-external-mstsc.md)

## Findings

| ID | Sev | Location | Issue | Evidence | Disposition |
|---|---|---|---|---|---|
| AAD-001 | P2 | (missing) | No Fake AAD routing despite external mstsc glue taking effective bool only | Task requires `PreferExternalMstsc` vs `EmbeddedOcx` + compose | **Fixed** — `aad_external_client_glue.rs` |
| AAD-002 | P2 | detection | Bare `*@*.onmicrosoft.com` could false-positive external | C# deliberately excludes; on-prem synced UPNs | **Fixed** — `onmicrosoft_upn_without_prefix_is_not_azure_ad` |
| AAD-003 | P2 | catalog | Lookup error must route external fail-safe | C# `ShouldUseExternalClient_CredentialLookupThrows_FailsSafeToExternal` | **Fixed** — `credential_lookup_error_fails_safe_to_external` |
| AAD-004 | P2 | order | Node AzureAD must not require catalog round-trip | Production crash: prompt-every-time + node domain | **Fixed** — `node_domain_short_circuits_before_catalog_lookup` |
| AAD-005 | P2 | compose | Tunnel + external must reject via composed glue | C# `AttachAsync_TunnelEnabled_…` path | **Fixed** — `glue_compose_tunnel_reject_when_external_and_tunnel_on` |
| AAD-006 | P3 | compose | Embedded must not bump external mstsc evaluate | Wasted policy / false launch eligibility | **Fixed** — `glue_embedded_skips_external_tunnel_evaluate` |
| AAD-007 | P3 | protocol | SSH credential with AzureAD domain must not force external | C# checks `credential.Protocol == Rdp` | **Fixed** — `non_rdp_credential_does_not_force_external` |
| AAD-008 | P3 | docs | Ledger + spike + matrix + README missing | Policy requires closed ledger | **Fixed** — this ledger + doc updates |
| AAD-R1 | — | `wormhole-session` wiring | Session `RdpConnectRequest` still uses profile flag only | Intentionally no surface-win dep in session | **Rejected** — deferred |
| AAD-R2 | — | Live CredMgr / storage catalog | Task requires scripted Fake only | `FakeRdpCredentialCatalog` is lab surface | **Rejected** — by design |
| AAD-R3 | — | Duplicate `external_mstsc_glue` | Could merge modules | User gate: compose, do not rewrite external glue | **Rejected** — composition only |
| AAD-R4 | — | `Process::Command` in tests | Could spawn mstsc for integration | Contract: Fake counters only | **Rejected** — held |

## Fixes applied

- `rdp/aad_external_client_glue.rs` — `has_azure_ad_*`, `resolve_rdp_routing`,
  `FakeRdpCredentialCatalog`, `RdpAadExternalClientGlue::evaluate_connect_route` composes
  `RdpExternalMstscGlue`
- `rdp/mod.rs` / `lib.rs` — exports + feature comment
- `Cargo.toml` — optional `uuid` on `rdp` feature for scripted catalog ids
- `docs/migration/05-rdp-spike.md` — works row, AAD section, re-audit pin
- `docs/migration/README.md` — ledger link
- `docs/migration/feature-matrix.md` — external mstsc row → Lab
- `docs/migration/adversarial-ledger-rdp-aad-external.md` — this ledger

## Gate record

### Adversarial loop

| Cycle | Strategy | Accepted findings | Result |
|---|---|---|---|
| Adv-0 | Contract → boundary → order → fail-safe → compose → no spawn → session dep | AAD-001…008 | Fixed (new module) |
| Adv-1 | Reverse: C# test matrix oracles; node short-circuit; embedded skips external evaluate; onmicrosoft negative | None (AAD-R1…R4 rejected) | Clean (1/2) |
| Adv-2 | Tests-as-oracles → docs pin → credential username prefix + missing row → Debug redaction | None | Clean (2/2) |

### Iterative-review-simplify

| Cycle | Reuse | Efficiency | Quality/Bugs | Accepted | Result |
|---|---|---|---|---|---|
| Sim-1 | Compose existing `RdpExternalMstscGlue`; pure `has_azure_ad_*` helpers | Scripted `HashMap` catalog; no I/O | Reject merging into external_mstsc_glue | None | Clean (1/3) |
| Sim-2 | `resolve_rdp_routing` + `evaluate_connect_route` split | Node signals before lookup | Non-Rdp credential guard | None | Clean (2/3) |
| Sim-3 | Exports via `rdp/mod.rs`; spike table matches | No hot-path work | AAD-R1…R4 remain rejected | None | Clean (3/3) |

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-surface-win --features rdp -- aad_external
```

Result: **pass** — 19 unit tests in `aad_external_client_glue.rs`.

```powershell
cargo test -p wormhole-surface-win --features rdp
```

Result: **pass** — full crate with `--features rdp` (no regressions).

## Residual notes

- Live `mstsc.exe` launch / crash-sentinel auto-flag remain deferred (no `Process::Command`).
- `wormhole-session` `RdpConnectRequest::try_from_profile` still reads `rdp_use_external_client`
  only — orchestrator wiring of AAD glue stays deferred (no surface-win dep).
- CredSSP / display / performance Fake glues unchanged.
- External mstsc tunnel message identity remains owned by `external_mstsc_glue` / `configure.rs`.
