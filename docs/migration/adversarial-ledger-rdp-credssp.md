# Adversarial ledger — RDP CredSSP / configure spike

Scope: `rust/crates/wormhole-surface-win/src/rdp/` configure / policy / password Zeroizing paths (`configure.rs`, `ocx.rs` configure, `dispatch.rs` soft put + AdvancedSettings helper), `docs/migration/05-rdp-spike.md` as needed  
Out of scope: C# sources (do not mutate); OLE/overlay hosting (prior ledgers); full gateway apply / resolution debounce  
Constraints: keep `GWLP_HWNDPARENT` overlay model; never log passwords; soft CredSSP miss must not be an undocumented half-config  
Baseline: `cargo test -p wormhole-surface-win --features rdp` green (54 tests before review)  
Design SoT: `docs/migration/05-rdp-spike.md`, AGENTS.md tunnel + RDP notes

## Findings

| ID | Sev | Location | Issue | Evidence | Disposition |
|---|---|---|---|---|---|
| CRED-001 | P1 | `rdp/ocx.rs` `configure` | Password left in `opts` on early validation / loud-put `Err` (only wiped after `take` at password put) | Failed empty-server path kept `Zeroizing` in caller opts; Debug of opts after Err could still show redacted presence; attack focus: wipe on all exits | **Fixed** — take password first + `WipePasswordOnDrop`; validation Err still wipes |
| CRED-002 | P1 | `ConfigureReport` / soft CredSSP | Soft CredSSP miss only pushed a generic “OCX default” string; no typed NLA-risk flag | Callers could `Connect` after half-config with `EnableCredSspSupport` stuck at false | **Fixed** — `cred_ssp_applied`, `cred_ssp_soft_missed`, `has_cred_ssp_risk()`, `CREDSSP_SOFT_MISS_NLA_RISK`; docs warn not to Connect |
| CRED-003 | P2 | `configure.rs` | No server/port/identity/desktop validation (empty server, port 0, NUL, oversized strings) | Empty/`"   "` server reached COM; oversized BSTR puts unbounded; password length errors must not echo secret | **Fixed** — `validate_rdp_configure_options` / `validate_configure_inputs` + limits; errors never include password |
| CRED-004 | P2 | `validate_tunnel_rdp_policy` tests | Gateway only tested as `1`; strict-only-vs-other-auth and gateway-before-strict under-pinned | False-Ok risk for nonzero gateway / auth≠1 not regression-locked | **Fixed** — negative/MAX gateway, auth∈{0,2,3,-1} allow, gateway-before-strict test |
| CRED-005 | P2 | soft CredSSP when `enable_cred_ssp=false` | Soft miss always appended NLA-risk text even when requested-off matches OCX default `false` | Misleading soft_failures / risk signal | **Fixed** — NLA soft miss only when CredSSP was requested on |
| CRED-006 | P3 | `configure_and_connect` | Lab helper Connects even if CredSSP soft-missed | Documented intentional; production must inspect report | **Fixed** — doc comment; not blocked as behavior for lab |
| CRED-007 | — | COM `BSTR` heap after `ClearTextPassword` | `VariantClear` frees but does not SecureZero BSTR | Platform/COM limitation | **Rejected** — residual; Rust-side Zeroizing covered; BSTR wipe would need extra unsafe |
| CRED-008 | — | Memory content assert after zeroize | Reading freed/zeroized buffer is UB/flaky | Prior weak test only asserted `is_none` | **Rejected** — keep API/opts-empty + Debug redaction tests |
| CRED-009 | — | `SetParent` / `WS_CHILD` | Attack constraint | Overlay path unchanged | **Rejected** — invariant held |

## Fixes applied

- `rdp/configure.rs` — tunnel policy docs/tests; `RdpConfigureOptions` Debug redaction; input validation + caps; `WipePasswordOnDrop`; `ConfigureReport` CredSSP/Negotiate status + NLA risk; shared `validate_configure_inputs`
- `rdp/ocx.rs` — configure takes password first, wipes on every exit; soft CredSSP NLA signaling; validation-failure wipe regression; `configure_and_connect` docs
- `rdp/dispatch.rs` — `get_advanced_settings` helper (9→2 fallback)
- `rdp/mod.rs` — export validation helpers + CredSSP constants / size caps
- `docs/migration/05-rdp-spike.md` — wipe-on-exit, soft CredSSP risk, validation, tunnel priority

## Gate record

### Adversarial loop

| Cycle | Strategy | Accepted findings | Result |
|---|---|---|---|
| Adv-0 (initial) | Contract → boundary → state → concurrency → security → integration → perf → tests | CRED-001…006 | Fixed; counter reset |
| Adv-1 | Same lanes on fixed tree | CRED-005 (requested-off soft miss noise) | Fixed; counter reset |
| Adv-2 | Reverse: tests-as-oracles → secrets/Debug → policy false-Ok → soft CredSSP → validation | None | Clean (1/2) |
| Adv-3 | Integration drift + half-config docs + GWLP/password grep | None | Clean (2/2) |

### Iterative-review-simplify (after adversarial clean)

| Cycle | Reuse | Efficiency | Quality/Bugs | Accepted | Result |
|---|---|---|---|---|---|
| Sim-fix | Duplicate wipe on validation Err vs guard | — | — | **Fixed** — take-first + shared `validate_configure_inputs` | Reset |
| Sim-fix | Duplicated AdvancedSettings9/2 lookup | — | — | **Fixed** — `get_advanced_settings` | Reset |
| Sim-1 | SoftPut arms left distinct (different report fields) — reject over-abstract | No hot-path I/O | Wipe-on-panic via `Zeroizing`/`WipePasswordOnDrop` intact | None | Clean (1/3) |
| Sim-2 | Public `validate_rdp_configure_options` wraps shared inputs | Fallback GetIDs unavoidable | Docs match wipe + NLA risk | None | Clean (2/3) |
| Sim-3 | Caps/constants exported once | Unit tests no COM for policy/validate | No password in error strings; GWLP unchanged | None | Clean (3/3) |

### Adversarial re-loop (required after simplify edits)

| Cycle | Strategy | Accepted | Result |
|---|---|---|---|
| Adv-R1 | Delta: take-first wipe + `validate_configure_inputs` + `get_advanced_settings`; panic between take and guard still Zeroizing-drops | None | Clean (1/2) |
| Adv-R2 | Reverse: Debug redaction, tunnel priority, soft CredSSP only when requested, no SetParent | None | Clean (2/2) |

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-surface-win --features rdp
cargo check -p wormhole-surface-win --features rdp
```

Result: **pass** — 68 unit tests with `--features rdp` (configure/policy/validation/wipe + prior OLE/overlay/focus suite).

## Residual notes

- COM `BSTR` for `ClearTextPassword` is not SecureZero’d by `VariantClear` (CRED-007).
- `configure_and_connect` is a lab helper and will Connect despite CredSSP soft miss; session layer must use `configure` + `ConfigureReport::has_cred_ssp_risk()`.
- Workspace pin note (out of CredSSP scope, needed to run cargo): `tokio-util` 0.7.19 has no `sync` feature — workspace uses `features = ["rt"]`.
